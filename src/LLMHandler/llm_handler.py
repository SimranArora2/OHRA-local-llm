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
        internal helper function that actually calls the LLM using langchain
        """
        # trim messages to not crash the context window
        trimmed_messages = trim_messages(
            messages=state["messages"],
            max_tokens=500,
            strategy="last",
            token_counter=self.__client,
            include_system=False,  # drop system prompt since we will add it again
            allow_partial=False,
            start_on="human",
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
