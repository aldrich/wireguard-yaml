import base64
import click
import difflib
import git
import ipaddress
import os
import re
import ruamel.yaml
import sys
from phabricator import Phabricator
from ruamel.yaml.main import round_trip_dump, round_trip_load
from typing import OrderedDict

# need to configure this per user
puppetRoot = '/Users/aldrichco/Work/puppet'
phabAPIToken = "api-7unflhaiccokaom4dzbavawvzoyo"
phabHost = "https://phabricator.tools.flnltd.com/api/"
wireguardManifestFilePath = "manifests/hieradata/role/wireguard_server.yaml"
repository = "rPP"
commit = "HEAD"
projectPHIDs = [  # new tickets are tagged with the following projects
    # 'PHID-PROJ-z4lum22ekior7wxtn7ub',  # access
    # 'PHID-PROJ-3ecog2unqfikccogkaeb',  # systems_engineering
]


# Globals
phab = Phabricator(host=phabHost, token=phabAPIToken)
repo = git.Repo(puppetRoot)


def getWireGuardServerYamlFile():
    # Use the Phabricator API to locate a file in a repository.
    file = phab.diffusion.filecontentquery(
        path=wireguardManifestFilePath, repository=repository, commit=commit)

    # Use the Phabricator API to download the file.
    # maybe also check if the file exists.
    return phab.file.download(phid=file.filePHID)


def getWireGuardManifestFileContents():
    click.echo('Fetching Wireguard maniphest YAML file from Phabricator API...')
    encodedFileContents = getWireGuardServerYamlFile().response
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


def generateDiff(username, publickey):

    fileContents = getWireGuardManifestFileContents().decode('utf-8')

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

    # surround the values with single quotes.
    # r'PublicKey: ([a-zA-Z0-9+=/]+)'
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

    path = puppetRoot
    if os.path.isdir(path):
        path = os.path.join(path, wireguardManifestFilePath)
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
        f'Updated file {wireguardManifestFilePath}.')

    ticketId = None
    if click.confirm(f'Do you also want to create a ticket?', default=False):
        ticketId = createTicket(username, publickey, ipAddress)

    commitChanges(username=username, ticketId=ticketId)

    os.chdir(puppetRoot)
    os.system('arc diff --browse --create --draft --nolint \
--skip-staging --nounit --verbatim')


def commitChanges(username, ticketId):
    repo.index.add([wireguardManifestFilePath])
    # Commit (and diff) title
    commitMessage = f'[TEST] VPN request for @{username}.'
    commitMessage += '\n\nSummary: This adds a wireguard peer entry for {username}.'
    if ticketId is not None:
        commitMessage += f'\n\nRef T{ticketId}'
    commitMessage += '\n\nTest Plan: peer review'
    repo.index.commit(commitMessage)
    click.echo('Successfully committed changes')


def createADifferential():
    #    create a diff.
    #     path1 = 'a/manifests/hieradata/role/wireguard_server.yaml'
    #     path2 = 'b/manifests/hieradata/role/wireguard_server.yaml'

    #     # array of lines.
    #     diff = difflib.unified_diff(
    #         fileContents.splitlines(),
    #         str.splitlines(),
    #         path1,
    #         path2
    #     )

    #     click.echo('-------- Here\'s the body of the raw diff ---------\n')
    #     click.echo('Go to https://phabricator.tools.flnltd.com/differential/diff/create/ \
    # and paste the following to Raw Diff to get started:\n')
    #     click.echo(
    #         '>>>>>> COPY EVERY LINE BELOW, UNTIL BUT NOT INCLUDING THE LINE WITH THE ">>>>>>END" MARKER')

    #     print('diff --git %s %s' % (path1, path2))
    #     for line in diff:
    #         click.echo(line.rstrip())

    #     click.echo('>>>>>>END\n')

    pass


def createTicket(username, publickey, ipaddress):
    # note we cannot link
    # this to the diff so some steps would have to be manual. But it could use the username and key,
    # and prefill some values.
    description = f'''
I would like VPN access for {username}. This is the Wireguard public key: `{publickey}`
'''

    transactions = [
        {
            'type': 'title',
            'value': f'VPN Request for @{username}',
        },
        {
            'type': 'description',
            'value': description
        },
        {
            'type': 'projects.set',
            'value': projectPHIDs
        },
        {
            'type': 'comment',
            'value': f'The IP Address for the Wireguard peer should be: `{ipaddress}/32`'
        }
    ]

    result = phab.maniphest.edit(transactions=transactions)
    ticketId = result.response['object']['id']
    click.echo(
        f'Maniphest ticket created at https://phabricator.tools.flnltd.com/T{ticketId}')
    return ticketId


@click.command()
@click.option('--username', '-u', prompt='Username', help='Phabricator username of the staff requesting vpn.')
@click.option('--publickey', '-k', prompt='Wireguard Public Key', help='A Wireguard public key shared by user')
def cli(username, publickey):
    try:
        createNewBranchInRepo(username, pull=False)
    except AssertionError as error:
        click.echo(f'There was an exception preparing the rPP repo. \
    Please fix the issue externally and then try again: {error}')
        return

    generateDiff(username, publickey)


def createNewBranchInRepo(username, pull=True):
    """ This function locates the puppet repo, updates the master branch,
    and creates a new branch with the named after the user in the param.
    This prepares the branch to be the staging area for the diff.
    """
    url = repo.remotes[0].config_reader.get('url')
    repoName = os.path.splitext(os.path.basename(url))[0]
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


if __name__ == '__main__':
    cli()
