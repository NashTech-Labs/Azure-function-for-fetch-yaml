import azure.functions as func
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
import requests
import base64
import yaml


def fetch_key_vault_secret(tenant_id: str, client_id: str, client_secret: str, secret_name: str) -> str:
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )

    client = SecretClient(
        vault_url="https://PATVault06.vault.azure.net/",
        credential=credential
    )

    secret = client.get_secret(secret_name)
    return secret.value

# fetch githbu file using github api call.
def fetch_github_file(owner, repo, ref, filepath, token):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filepath}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        content = response.json()
        if content.get("type") == "file":
            return content["content"]
        else:
            print(f"Error: {filepath} is not a file.")
    else:
        print(f"Error: Failed to fetch file {filepath} (Status Code: {response.status_code})")
    return ""


def decode_base64(content):
    decoded_content = base64.b64decode(content).decode("utf-8")
    return decoded_content


def get_resource_types_list(content):
    resources = []

    for component in content:
        resources.append(component['type'])

    return resources


# this function is not calling now we can use this function for the perticular branch.

def fetch_branches_starting_with(owner, repo, token, prefix):
    url = f"https://api.github.com/repos/{owner}/{repo}/branches"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        branches = [branch["name"] for branch in response.json()]
        filtered_branches = [branch for branch in branches if branch.lower().startswith(prefix.lower())]
        return filtered_branches
    else:
        print(f"Error: Failed to fetch branches (Status Code: {response.status_code})")
        return []



def main(req: func.HttpRequest) -> func.HttpResponse:
    # Set your Azure Key Vault and credential details
    client_id = "<>"
    client_secret = "<>"
    tenant_id = "<>"
    ref = "<>"
    filepath_compute = "<>" 
    owner="<>"
    repo="<>"
    prefix="<>"

    # Fetch secrets from Key Vault
    secret_name1 = "<>"
    secret_value1 = fetch_key_vault_secret(tenant_id, client_id, client_secret, secret_name1)
    print(f"Secret value for {secret_name1}: {secret_value1}")

    secret_name2 = "<>"
    secret_value2 = fetch_key_vault_secret(tenant_id, client_id, client_secret, secret_name2)
    print(f"Secret value for {secret_name2}: {secret_value2}")

    file_content_compute = fetch_github_file(owner, repo, ref, filepath_compute, secret_value1)

    if file_content_compute:
        # Decode the base64 content
        decoded_content = decode_base64(file_content_compute)
        try:
            decoded_data = yaml.safe_load(decoded_content)
            if isinstance(decoded_data, dict):
                resource_type = get_resource_types_list(decoded_data.get('shared-resources', []))
                print(f"Resource types: {resource_type}")
            else:
                print("Error: Failed to parse YAML file. Content is not a dictionary.")
        except Exception as e:
            print(f"Error: Failed to parse YAML file. {str(e)}")
    else:
        print("Error: Failed to fetch the file from GitHub.")

    # Return a response
    return func.HttpResponse("Azure Function executed successfully.", status_code=200)


if __name__ == '__main__':
    dummy_req = func.HttpRequest(method='GET', url="http://localhost:7071/api/< >")
    main(dummy_req)