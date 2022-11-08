#%%
import json
import sys
import time
import webbrowser
import http.client
import logging
from globus_sdk import NativeAppAuthClient, RefreshTokenAuthorizer, TransferClient, TransferData, TransferAPIError
from globus_sdk.exc import GlobusAPIError


#%% Input parameters
TOKEN_FILE = "./.refresh-tokens.json"
CLIENT_ID ="8cba22bd-c84b-44c1-95dd-40424099e900"
REDIRECT_URI = "https://auth.globus.org/v2/web/auth-code"
SCOPES = 'urn:globus:auth:scope:transfer.api.globus.org:all[*https://auth.globus.org/scopes/65194284-3dc1-4b0f-bc3c-2921c96c31cb/data_access]'
TUTORIAL_ENDPOINT_ID = "65194284-3dc1-4b0f-bc3c-2921c96c31cb"

source_endpoint_id="65194284-3dc1-4b0f-bc3c-2921c96c31cb"  # jb62 condo
dest_endpoint_id="9f0d700a-3a96-11ed-ba4b-d5fb255a47cc"  # Fu's Macbook



#%% Functions
# uncomment the next line to enable debug logging for network requests
# enable_requests_logging()

def enable_requests_logging():
    http.client.HTTPConnection.debuglevel = 4

    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


def is_remote_session():
    return os.environ.get("SSH_TTY", os.environ.get("SSH_CONNECTION"))


def load_tokens_from_file(filepath):
    """Load a set of saved tokens."""
    with open(filepath, "r") as f:
        tokens = json.load(f)

    return tokens


def save_tokens_to_file(filepath, tokens):
    """Save a set of tokens for later use."""
    with open(filepath, "w") as f:
        json.dump(tokens, f)


def update_tokens_file_on_refresh(token_response):
    """
    Callback function passed into the RefreshTokenAuthorizer.
    Will be invoked any time a new access token is fetched.
    """
    save_tokens_to_file(TOKEN_FILE, token_response.by_resource_server)


def do_native_app_authentication(client_id, redirect_uri, requested_scopes=None):
    """
    Does a Native App authentication flow and returns a
    dict of tokens keyed by service name.
    """
    client = NativeAppAuthClient(client_id=client_id)
    # pass refresh_tokens=True to request refresh tokens
    client.oauth2_start_flow(
        requested_scopes=requested_scopes,
        redirect_uri=redirect_uri,
        refresh_tokens=True,
    )

    url = client.oauth2_get_authorize_url()

    print("Native App Authorization URL: \n{}".format(url))

    if not is_remote_session():
        webbrowser.open(url, new=1)

    auth_code = input("Enter the auth code: ").strip()

    token_response = client.oauth2_exchange_code_for_tokens(auth_code)

    # return a set of tokens, organized by resource server name
    return token_response.by_resource_server


def main():
    tokens = None
    try:
        # if we already have tokens, load and use them
        tokens = load_tokens_from_file(TOKEN_FILE)
    except:
        pass

    if not tokens:
        # if we need to get tokens, start the Native App authentication process
        tokens = do_native_app_authentication(CLIENT_ID, REDIRECT_URI, SCOPES)

        try:
            save_tokens_to_file(TOKEN_FILE, tokens)
        except:
            pass

    transfer_tokens = tokens["transfer.api.globus.org"]

    auth_client = NativeAppAuthClient(client_id=CLIENT_ID)

    authorizer = RefreshTokenAuthorizer(
        transfer_tokens["refresh_token"],
        auth_client,
        access_token=transfer_tokens["access_token"],
        expires_at=transfer_tokens["expires_at_seconds"],
        on_refresh=update_tokens_file_on_refresh,
    )

    transfer = TransferClient(authorizer=authorizer)

    #%% 1.list files
    # print out a directory listing from an endpoint
    try:
        transfer.endpoint_autoactivate(TUTORIAL_ENDPOINT_ID)
    except GlobusAPIError as ex:
        print(ex)
        if ex.http_status == 401:
            sys.exit(
                "Refresh token has expired. "
                "Please delete refresh-tokens.json and try again."
            )
        else:
            raise ex

    for entry in transfer.operation_ls(TUTORIAL_ENDPOINT_ID, path="/~/"):
        print(entry["name"] + ("/" if entry["type"] == "dir" else ""))

    # revoke the access token that was just used to make requests against
    # the Transfer API to demonstrate that the RefreshTokenAuthorizer will
    # automatically get a new one
    auth_client.oauth2_revoke_token(authorizer.access_token)
    # Allow a little bit of time for the token revocation to settle
    time.sleep(1)
    # Verify that the access token is no longer valid
    token_status = auth_client.oauth2_validate_token(transfer_tokens["access_token"])
    assert token_status["active"] is False, "Token was expected to be invalid."

    print("\nDoing a second directory listing with a new access token:")
    for entry in transfer.operation_ls(TUTORIAL_ENDPOINT_ID, path="/~/"):
        print(entry["name"] + ("/" if entry["type"] == "dir" else ""))


    #%% 2. transfer data
    task_data = TransferData(transfer, source_endpoint_id, dest_endpoint_id)
    task_data.add_item(
        "/hpc-demo/docs/",  # source
        # "/~/Valencia/Matlab_read_data_example/html/",
        "~/workspace/7/",  # Fu's Macbook
        recursive=True
        )
    task_doc = transfer.submit_transfer(task_data)
    task_id = task_doc["task_id"]
    print(f"\nsubmitted transfer, task_id={task_id}")

    #%% 3.get scopes if you don't know
    # try:
    #     task_doc = transfer.submit_transfer(task_data)
    # except TransferAPIError as err:
    #     if err.info.consent_required:
    #         print(
    #             "Got a ConsentRequired error with scopes:",
    #             err.info.consent_required.required_scopes,
    #         )
    #     else:
    #         raise

if __name__ == "__main__":
    main()



