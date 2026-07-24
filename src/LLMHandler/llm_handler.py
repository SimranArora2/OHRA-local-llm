"""
This file contains the class that handles the LLM requests, i.e.
sending requests to the LLM API and processing the responses
"""

import os

from datetime import datetime
from typing import Sequence

from langchain.chat_models import init_chat_model
# from langchain_core.globals import set_llm_cache
# from langchain_core.caches import InMemoryCache

from langchain_core.messages import BaseMessage, HumanMessage, trim_messages
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from langgraph.graph.message import add_messages
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import START, StateGraph

from typing_extensions import Annotated, TypedDict

# ── Threat-Weighted Memory Pruning (MIRAGE contribution) ──────────────────────
import re as _re

_COMMAND_WEIGHTS = {
    "ls": 0.1, "pwd": 0.1, "whoami": 0.2, "id": 0.2,
    "uname": 0.2, "ifconfig": 0.3, "netstat": 0.3, "ip": 0.3,
    "hostname": 0.2, "cat /etc/os-release": 0.2,
    "find": 0.4, "cat /etc/passwd": 0.6, "cat /etc/shadow": 0.6,
    "ps": 0.4, "env": 0.5, "cat": 0.4, "grep": 0.4,
    "history": 0.5, "last": 0.5,
    "wget": 0.9, "curl": 0.9, "nc": 0.8, "bash -i": 0.9,
    "python -c": 0.8, "python3 -c": 0.8, "perl -e": 0.8,
    "php -r": 0.8, "ncat": 0.8, "mkfifo": 0.7,
    "chmod": 0.8, "chown": 0.8, "crontab": 0.9, "useradd": 0.9,
    "ssh-keygen": 0.85, "rm -rf": 0.85, "passwd": 0.9,
    "visudo": 0.95, "systemctl": 0.8,
}
_HIGH_RISK_PATTERNS = [
    (_re.compile(r'find.*-perm.*[su]'), 0.7),
    (_re.compile(r'/tmp/[^\s]+'), 0.8),
    (_re.compile(r'/dev/shm/[^\s]+'), 0.8),
    (_re.compile(r'base64\s+-d'), 0.8),
    (_re.compile(r'echo.*>>.*\.ssh/'), 0.95),
    (_re.compile(r'authorized_keys'), 0.95),
]
_SEPARATORS = _re.compile(r'&&|\|\|?|;|&')

def _score_command(command: str) -> float:
    """Score a command by pen-test stage weight. Returns 0.0-1.0."""
    atoms = [c.strip() for c in _SEPARATORS.split(command) if c.strip()]
    weights = []
    for atom in atoms:
        w = 0.1
        for pattern, pw in _HIGH_RISK_PATTERNS:
            if pattern.search(atom):
                w = pw
                break
        else:
            if atom in _COMMAND_WEIGHTS:
                w = _COMMAND_WEIGHTS[atom]
            else:
                for key, kw in _COMMAND_WEIGHTS.items():
                    if atom.startswith(key):
                        w = kw
                        break
            if atom.startswith('/tmp') or atom.startswith('./'):
                w = max(w, 0.8)
        weights.append(w)
    return max(weights) if weights else 0.1

def _threat_aware_prune(messages, max_tokens: int = 500) -> list:
    """
    Prune messages by threat score — keeps HIGH threat commands longer.
    Falls back to last-N if scoring not applicable.
    Low-score (recon) commands pruned first, high-score (exploit) kept.
    """
    from langchain_core.messages import HumanMessage, AIMessage
    if not messages:
        return messages

    # score each human message
    scored = []
    for i, msg in enumerate(messages):
        if isinstance(msg, HumanMessage):
            score = _score_command(str(msg.content))
        else:
            score = None  # AI responses inherit score of preceding human msg
        scored.append((i, msg, score))

    # propagate human scores to following AI responses
    last_score = 0.1
    for i, (idx, msg, score) in enumerate(scored):
        if score is not None:
            last_score = score
        else:
            scored[i] = (idx, msg, last_score)

    # always keep last 2 exchanges regardless of score
    if len(messages) <= 4:
        return messages

    # sort by score ascending — lowest scored get pruned first
    # but preserve chronological order after pruning
    candidates = scored[:-4]  # never prune last 2 exchanges
    always_keep = scored[-4:]

    # prune lowest scoring messages until under token estimate
    # rough estimate: 1 token ≈ 4 chars
    def token_estimate(msgs):
        return sum(len(str(m.content)) for _, m, _ in msgs) // 4

    candidates_sorted = sorted(candidates, key=lambda x: x[2])
    kept_candidates = list(candidates)

    while token_estimate(kept_candidates + always_keep) > max_tokens and kept_candidates:
        # remove lowest scoring candidate
        lowest = min(kept_candidates, key=lambda x: x[2])
        kept_candidates.remove(lowest)

    # restore chronological order
    final = sorted(kept_candidates + always_keep, key=lambda x: x[0])
    return [msg for _, msg, _ in final]
# ── End Threat-Weighted Memory Pruning ────────────────────────────────────────


class State(TypedDict):
    """
    class for the custom state with a variable system prompt
    """

    messages: Annotated[Sequence[BaseMessage], add_messages]
    system_prompt: str


class LLMHandler:
    """
    The LLM Handler class
    When initializing provide it with the following:
    - protocol_prompts: dict => dictionary holding protocol name as key and
        path to respective system prompt as value
    - model: str => name of the model to use, default is gpt-4o-mini
    - provider: str => name of the provider, needs to match model, default is openai

    During init can raise the following exceptions:
    - FileNotFoundError: a specified system prompt was not found
    - ValueError: model_provider cannot be inferred or is not supported OR
        provided wrong format for protocol prompts
    - ImportError: model provider integration package is not installed
        (default only openai is installed)
    """

    def __init__(
        self,
        protocol_prompts: dict,
        model: str = "gpt-4o-mini",
        provider: str = "openai",
    ):
        # validate protocol_prompts
        if not isinstance(protocol_prompts, dict):
            raise ValueError("Did not specify correct protocol prompts")

        self.__proto_prompts = protocol_prompts

        # validate that all system prompts are readable and existent
        for proto, path in self.__proto_prompts.items():
            if not os.path.isfile(path):
                raise FileNotFoundError(f"Proto: {proto}, Given path: {path}")

        # set the general form of the system prompt
        self.__prompt_template = ChatPromptTemplate.from_messages(
            [
                ("system", "{system_prompt}"),
                MessagesPlaceholder(variable_name="messages"),
            ]
        )

        if provider == "ollama":
            self.__client = init_chat_model(
                model, model_provider=provider, temperature=0.5,
                base_url="http://host.docker.internal:11434"
            )
        else:
            self.__client = init_chat_model(model, model_provider=provider, temperature=0.5)

        # setup langchain for memory handling - enabling session states identified by sessionIDs
        workflow = StateGraph(state_schema=State)
        workflow.add_edge(START, "model")
        workflow.add_node("model", self.__call_model)
        memory = MemorySaver()
        self.__handler = workflow.compile(checkpointer=memory)
        # set_llm_cache(InMemoryCache())

    def __read_system_prompt(self, filepath: str):
        """
        internal helper function to set the system prompt
        from a file

        Will raise FileNotFoundError upon not finding the system prompt file
        which should never happen as it is validated during init

        Will raise OSError if there is an issue with reading the system prompt file
        """
        prompt = ""
        if not os.path.isfile(filepath):
            raise FileNotFoundError(
                f"Could not find system prompt input file '{filepath}'"
            )

        with open(filepath, mode="r", encoding="utf-8") as f:
            prompt = f.read()
        return prompt

    def __call_model(self, state: State):
        """
        internal helper function that actually calls the LLM using langchain.
        Uses threat-weighted memory pruning (MIRAGE) instead of naive last-N.
        High-threat commands (exploit/post-exploit) are retained longer in context.
        Low-threat commands (recon) are pruned first when context fills up.
        """
        # threat-aware pruning — keeps high-score commands in context longer
        trimmed_messages = _threat_aware_prune(
            state["messages"], max_tokens=500
        )
        # create the prompt for this protocol, including also the state
        prompt = self.__prompt_template.invoke(
            {"messages": trimmed_messages, "system_prompt": state["system_prompt"]}
        )

        # send the message to the LLM
        response = self.__client.invoke(prompt)
        return {"messages": [response]}

    def get_response(
        self, protocol: str, user_in: str, session_id: str, username: str
    ) -> str | None:
        """
        Public function to get the model response.
        It will do some basic checking of the LLM output to ensure
        that the LLM does not reveal itself.

        Note: Protocol specific checks are not performed here and should be
        handled in the respective code before/after calling this function
        """
        # check that the protocol is supported
        if protocol not in self.__proto_prompts:
            raise KeyError(f"Provided protocol {protocol} not supported")

        # read the system prompt for this protocol
        system_prompt = self.__read_system_prompt(self.__proto_prompts[protocol])

        # extend the system prompt by the current date and minute
        time = f"The current date and time is: {datetime.today().strftime('%Y-%m-%d %H:%M')}"
        system_prompt = "\n".join([system_prompt, time])
        # extend the system prompt by the username that was used for authentication
        # this may be set to "None" as it is not applicable for all protocols
        if username != "None":
            username_prompt = f"The user is logged in as: {username}"
            system_prompt = "\n".join([system_prompt, username_prompt])

        # set the sessionID to include potential previous messages
        config = {"configurable": {"thread_id": session_id}}
        input_message = [HumanMessage(user_in)]
        output = self.__handler.invoke(
            {"messages": input_message, "system_prompt": system_prompt}, config
        )
        return output["messages"][-1].text()
