import base64
import click
import configparser
import git
import ipaddress
import os
import re
from phabricator import Phabricator
from ruamel.yaml.main import round_trip_dump, round_trip_load
from typing import OrderedDict

# Globals: should be overwritten after loading config
#
# Get these from config.ini
PuppetRoot = ''
PhabricatorAPIToken = ''
PhabricatorHost = ''
WireguardManifestFilePath = ''
RepositoryName = ''
RepositoryCommit = ''
PHIDsOfProjectsToNotify = []  # new tickets are tagged with the following projects
# Reinitialize these after loading config variables
phab = Phabricator()
repo = git.Repo()


def getWireGuardServerYamlFile(phab):
    # Use the Phabricator API to locate a file in a repository.
    file = phab.diffusion.filecontentquery(
        path=WireguardManifestFilePath, repository=RepositoryName, commit=RepositoryCommit)

    # Use the Phabricator API to download the file.
    # maybe also check if the file exists.
    return phab.file.download(phid=file.filePHID)


def getWireGuardManifestFileContents(phab):
    click.echo('Fetching Wireguard maniphest YAML file from Phabricator API...')
    encodedFileContents = getWireGuardServerYamlFile(phab).response
    fileContents = base64.b64decode(encodedFileContents)
    return fileContents


def getNextValidIpAddress(peersYamlObj):
    # You will need to pick an IP address within the iprange 10.3.128.1/17
    # (10.3.128.1 - 10.3.255.254), which does not already belong to a
    # different user.

    # IP addresses already found in the YAML
    registeredIPAddresses = set()
    for username, peerInfo in peersYamlObj.items():
        registeredIPAddresses.add(peerInfo['IPAddress'])

    # get one IP address that's not them
    subnetList = list(ipaddress.IPv4Network('10.3.128.0/17').hosts())
    subnetList.reverse()
    hostsInSubnet = [str(host) for host in subnetList]

    for host in hostsInSubnet:
        if host not in registeredIPAddresses:
            return host
    return None


def generateDiff(phab, repo, username, publickey):

    fileContents = getWireGuardManifestFileContents(phab).decode('utf-8')

    # TESTING with ruamel.yaml
    code = round_trip_load(fileContents, preserve_quotes=True)

    # make the modifications
    peers = code['wireguard_server::wireguard_peers']

    # we know the keys should be sorted, but make no assumption
    # on the manifest that they indeed are. Let's just do a
    # best-effort search for the appropriate insertion index
    orderedPeers = OrderedDict(peers.copy())
    peersList = list(orderedPeers.keys())

    ipAddress = getNextValidIpAddress(orderedPeers)

    index = 0
    for key in peersList:
        if key > username:
            break
        index += 1

    peers.insert(index, username, {
        'PublicKey': publickey,
        'IPAddress': ipAddress
    })

    fileContents = round_trip_dump(code, block_seq_indent=2,
                                   explicit_start=True)

    # surround the values with single quotes to match the rest of the
    # YAML file, as library we used doesn't supply the new values with quotes.
    fileContents = re.sub(r'PublicKey: ([a-zA-Z0-9+=/]+)',
                          f'PublicKey: \'{publickey}\'', fileContents)
    fileContents = re.sub(r'IPAddress: ([0-9.]+)',
                          f'IPAddress: \'{ipAddress}\'', fileContents)

    if username in peersList and not click.confirm(f'The username \'{username}\' already exists in \
the Wireguard peers registry, continue?', default=False):
        click.echo('Operation aborted.')
        return

    click.echo(f'The next valid IP Address in the subrange 10.3.128.1/17 \
appears to be: {ipAddress}')

    path = PuppetRoot
    if os.path.isdir(path):
        path = os.path.join(path, WireguardManifestFilePath)
    else:
        click.echo(
            'Not a directory! Please correctly specify the puppet repo root.')
        return

    if not os.path.isfile(path):
        click.echo(f'Unable to open {path}, is it a file?')
        return

    wireguardManifest = open(path, "w")
    wireguardManifest.write(fileContents)
    wireguardManifest.close()

    click.echo(
        f'Updated file {WireguardManifestFilePath}.')

    ticketId = None
    if click.confirm(f'Do you also want to create a ticket?', default=True):
        ticketId = createTicket(phab, username, publickey, ipAddress)

    commitChanges(repo, username=username, ticketId=ticketId)

    # execute arc diff to prepare a diff for a syseng reviewer.
    os.chdir(PuppetRoot)

    command = 'arc diff --browse --create --draft --nolint \
--skip-staging --nounit --verbatim'
    click.echo(f'Running shell command: {command}')
    os.system(command)


def commitChanges(repo, username, ticketId):
    repo.index.add([WireguardManifestFilePath])
    # Commit (and diff) title
    commitMessage = f'[TEST] Make @{username} a Wireguard VPN peer'
    commitMessage += f'\n\nSummary: This adds a wireguard peer entry for \
@{username} in `{WireguardManifestFilePath}`.'
    if ticketId is not None:
        commitMessage += f'\n\nRef T{ticketId}'
    commitMessage += '\n\nTest Plan: SysEng/Access review'
    repo.index.commit(commitMessage)
    click.echo('Successfully committed changes')


def createTicket(phab, username, publickey, ipaddress):

    description = f'''
This is a VPN access request for @{username}.

The following is the public key to be registered with the Wireguard server (which is generated by @{username}):

```
{publickey}
```
'''

    transactions = [
        {
            'type': 'title',
            'value': f'[TEST] VPN Request for @{username}',
        },
        {
            'type': 'description',
            'value': description
        },
        {
            'type': 'projects.set',
            'value': PHIDsOfProjectsToNotify
        },
        {
            'type': 'comment',
            'value': f"""
A Wireguard VPN config request has been made for you. This should be \
your IP Address: `{ipaddress}/32`.

To setup, please download the template config file: {{F2198467}}

Open it and change the following values in the `[INTERFACE]` section:

- `YOUR_PRIVATE_KEY`: should be your Wireguard VPN **private key**. \
NOTE: Make sure you do not use your //public// key here.
- `YOUR_IP_ADDRESS/32`: should be `{ipaddress}/32`

Here is an example:

{{F2198468}}

Save the file. This will be used for setting up your Wireguard VPN \
configuration. Please reach out to #it_helpdesk if you need help \
in setting up Wireguard VPN in your computer.

NOTE: Afterwards, be sure to always keep the file in a secure location.
"""
        }
    ]

    result = phab.maniphest.edit(transactions=transactions)
    ticketId = result.response['object']['id']
    click.echo(
        f'Maniphest ticket created at https://phabricator.tools.flnltd.com/T{ticketId}')
    return ticketId


def loadConfig():

    global PuppetRoot
    global PhabricatorAPIToken
    global PhabricatorHost
    global WireguardManifestFilePath
    global RepositoryName
    global RepositoryCommit
    global PHIDsOfProjectsToNotify

    click.echo('Loading config...')
    config = configparser.ConfigParser()
    config.read('config.ini')

    params = config['Params']

    PuppetRoot = params['puppet_root']

    PhabricatorAPIToken = params['phabricator_api_token']
    PhabricatorHost = params['phabricator_host']
    WireguardManifestFilePath = params['wireguard_manifest_file_path']
    RepositoryName = params['puppet_repository_name']
    RepositoryCommit = params['puppet_repository_commit']

    projects = config['Projects_To_Tag']
    PHIDsOfProjectsToNotify = [projects[slug] for slug in projects.keys()]


def createNewBranchInRepo(repo, username, pull=True):
    """ This function locates the puppet repo, updates the master branch,
    and creates a new branch with the named after the user in the param.
    This prepares the branch to be the staging area for the diff.
    """
    click.echo(PuppetRoot)
    url = repo.remotes[0].config_reader.get('url')
    repoName = os.path.splitext(os.path.basename(url))[0]
    click.echo(url)
    assert repoName == 'puppet', 'Repo name should be puppet'

    assert not repo.is_dirty(
        untracked_files=True), 'Repository is dirty. Please make sure \
the repository is clean (by doing a `git stash` or `git reset --hard`).'

    click.echo(f'Repo `{repoName}` located, is clean')

    click.echo('Checking out master branch')
    repo.heads.master.checkout()
    assert not repo.head.is_detached, 'Repository head is detached. Please switch to master.'

    if pull:
        click.echo('Switched to master branch. Pulling latest')
        repo.remotes.origin.pull()

    # create a new branch ...
    branchName = f'wireguard/vpn_request_{username}'
    newBranch = repo.create_head(branchName)
    assert repo.active_branch != newBranch, 'Branch names don\'t match'

    newBranch.checkout()
    click.echo(f'Created and switched to `{branchName}`')


@click.command()
@click.option('--username', '-u', prompt='Username', help='Phabricator username of the staff requesting vpn.')
@click.option('--publickey', '-k', prompt='Wireguard Public Key', help='A Wireguard public key shared by user')
def cli(username, publickey):
    loadConfig()

    repo = git.Repo(PuppetRoot)
    phab = Phabricator(host=PhabricatorHost, token=PhabricatorAPIToken)

    try:
        createNewBranchInRepo(repo, username, pull=False)
    except AssertionError as error:
        click.echo(f'There was an exception preparing the rPP repo. \
Please fix the issue externally and then try again: {error}')
        return

    generateDiff(phab, repo, username, publickey)


if __name__ == '__main__':
    cli()
