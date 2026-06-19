"""
This file holds the class that defines the
format of a LLM response
"""
from pydantic import BaseModel

class LLMResponse(BaseModel):
    """
    This class defines the format that the LLM has to adhere to.
    This is a feature of openai.
    See https://platform.openai.com/docs/guides/structured-outputs for more info
    """
    response: str
