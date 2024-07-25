from dotenv import dotenv_values

config_token = dotenv_values(".env")

ALGORITHM = config_token["ALGORITHM"]
SECRET_KEY = config_token["SECRET_KEY"]
ACCESS_TOKEN_EXPIRE_MINUTES = config_token["ACCESS_TOKEN_EXPIRE_MINUTES"]