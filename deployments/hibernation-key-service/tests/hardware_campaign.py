#!/usr/bin/env python3
"""Bounded, loopback-only mTLS test on the two explicitly authorized TPM hosts.

Requires the existing read-only inventory probe image. Never reads unrelated NV
contents, changes host configuration, or clears a TPM. Refuses an existing task
state directory. On failure preserves state and reports cleanup requirements.
"""
import concurrent.futures
import io
import hashlib
import os
import re
import json
import pathlib
import shlex
import subprocess
import sys
import tarfile
import time

TARGETS = {'nas': ('admin@nas.home.hawara.nz', '0'),
           'overseer': ('hawara@overseer.srv.hwr.one', '113')}
target, binary, output = sys.argv[1:]
host, gid = TARGETS[target]
campaign = os.environ.get('HIBERNATION_CAMPAIGN', '20260920')
if not re.fullmatch(r'[a-z0-9-]{1,32}', campaign):
    raise ValueError('invalid campaign identifier')
base = '/tmp/orion-hibernation-mtls-' + campaign
name = 'orion-hibernation-mtls-' + campaign
image = 'orion-hibernation-mtls:' + campaign
ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ForwardAgent=no',
       '-o', 'ControlMaster=no', '-o', 'ControlPath=none', host]
result = {'target': target, 'tests': {}, 'binarySHA256': hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()}

def remote(args, data=None, success=True):
    p = subprocess.run(ssh + [shlex.join(args)], input=data, capture_output=True)
    if success and p.returncode:
        raise RuntimeError(p.stderr.decode() + p.stdout.decode())
    if not success:
        if p.returncode == 0:
            raise RuntimeError('negative test unexpectedly succeeded')
        return None
    return p.stdout.decode()

def docker(args, data=None, success=True):
    return remote(['sudo', '-n', 'docker'] + args, data, success)

limits = ['--network=none', '--read-only', '--cap-drop=ALL',
          '--security-opt=no-new-privileges', '--memory=128m',
          '--memory-swap=128m', '--pids-limit=64', '--ulimit=core=0',
          '--group-add=' + gid, '--device=/dev/tpmrm0:/dev/tpmrm0:rw']
mounts = ['--mount=type=bind,src=' + base + '/server,dst=/state',
          '--mount=type=bind,src=' + base + '/clients,dst=/clients']

def inventory():
    return json.loads(docker(['run', '--rm'] + limits +
                             ['orion-tpm-probe:20260919', 'inspect', target]))

def admin(operation, **kwargs):
    return json.loads(docker(['exec', '-i', name, '/key-service', 'admin'],
                            json.dumps({'operation': operation, **kwargs}).encode()))

def client(action, payload=None, success=True):
    args = ['exec', '-i', name, '/key-service', action,
            '--endpoint=https://127.0.0.1:19444', '--ca-file=/state/ca.crt',
            '--provider-id=' + provider, '--cluster-id=mtls-probe-cluster',
            '--node-uid=mtls-probe-' + target,
            '--registration-uid=mtls-probe-registration', '--state-dir=/clients/main']
    text = docker(args, None if payload is None else json.dumps(payload).encode(), success)
    return None if text is None else json.loads(text)

vm = 'mtls-probe-vm-' + target
attempt = 'mtls-probe-attempt-' + campaign
key_id = ''
def op(operation, success=True):
    payload = {'operation': operation, 'vmUID': vm, 'attemptID': attempt}
    if operation in ('open', 'consume', 'finalize'):
        payload['keyID'] = key_id
    if operation in ('open', 'consume', 'finalize'):
        payload.update(restoreVMIUID='mtls-restore-vmi', artifactDigest='a' * 64)
    return client('client-operation', payload, success)

def start():
    docker(['run', '-d', '--name', name] + limits + mounts +
           [image, 'serve', '--listen=127.0.0.1:19444'])
    for _ in range(30):
        try:
            admin('inspect')
            return
        except RuntimeError:
            time.sleep(0.3)
    raise RuntimeError('service failed to become ready')

def stop(crash=False):
    docker(['kill', '--signal=KILL', name] if crash else ['stop', '-t', '10', name])
    docker(['rm', name])

# No overwrite: a failed previous campaign must be inspected explicitly.
remote(['sudo', '-n', 'mkdir', '-m', '0700', base])
remote(['sudo', '-n', 'mkdir', '-m', '0700', base + '/server', base + '/clients'])
archive = io.BytesIO()
with tarfile.open(fileobj=archive, mode='w') as tar:
    tar.add(binary, arcname='key-service')
    data = b'FROM scratch\nCOPY key-service /key-service\nENTRYPOINT ["/key-service"]\n'
    info = tarfile.TarInfo('Containerfile'); info.size = len(data); info.mode = 0o600
    tar.addfile(info, io.BytesIO(data))
remote(['sudo', '-n', 'tar', '-xf', '-', '-C', base], archive.getvalue())
docker(['build', '-f', base + '/Containerfile', '-t', image, base])
result['before'] = inventory()
created = False
try:
    initialized = json.loads(docker(['run', '--rm'] + limits + mounts +
                                    [image, 'init', '--hostname=127.0.0.1']))
    provider = initialized['providerID']; result['providerID'] = provider
    start()
    pending = client('client-enroll')
    assert not pending['approved'] and not pending.get('certificate')
    op('create', success=False)
    # Fingerprint comes from the node-local public marker via authenticated SSH.
    marker = json.loads(remote(['sudo', '-n', 'cat', base + '/clients/main/identity.json']))
    assert pending['fingerprint'] == marker['fingerprint']
    admin('approve', requestID=pending['requestID'], fingerprint=marker['fingerprint'])
    enrolled = client('client-enroll'); assert enrolled['approved']
    op('create', success=False)
    admin('grant', requestID=pending['requestID'],
          grant={'clusterID': 'mtls-probe-cluster', 'vmUID': vm})
    result['tests']['approval_without_grant_rejected'] = True
    created_result = op('create'); created = True
    key_id = created_result['result']['key']['ID']
    stop(crash=True); start()
    assert op('open')['keyVerified']
    result['tests']['replacement_open_roundtrip'] = True
    # Snapshot only public ownership metadata while its writer is stopped.
    stop()
    remote(['sudo', '-n', 'cp', '--preserve=mode', base + '/server/metadata.db', base + '/metadata-before-consume.db'])
    start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: op('consume'), range(2)))
    assert sum(r['result']['fresh'] for r in results) == 1
    result['tests']['exactly_one_fresh_consumer'] = True
    stop(crash=True)
    remote(['sudo', '-n', 'cp', '--preserve=mode', base + '/metadata-before-consume.db', base + '/server/metadata.db'])
    start()
    assert not op('consume')['result']['fresh']
    op('open', success=False)
    result['tests']['rollback_and_lost_reply_cannot_replay'] = True
    assert op('finalize')['result']['erased']
    assert op('finalize')['result']['erased']
    created = False
    op('open', success=False)
    result['tests']['erasure_and_replay_rejection'] = True
    admin('renew-server')
    assert client('client-enroll')['approved']
    result['tests']['server_certificate_renewal'] = True
    admin('revoke', requestID=pending['requestID'])
    op('status', success=False)
    result['tests']['revoked_client_rejected'] = True
    stop()
    result['after'] = inventory()
    for kind in ('persistent', 'nv'):
        assert result['before'][kind] == result['after'][kind], 'original TPM objects changed'
    result['original_objects_unchanged'] = True
    remote(['sudo', '-n', 'rm', '-f', base + '/server/ca.key', base + '/server/server.key', base + '/clients/main/client.key'])
    result['test_credentials_removed'] = True
    result['passed'] = True
except Exception as exc:
    result['passed'] = False
    result['error'] = str(exc)
    result['cleanup_required'] = created
    # Preserve all state for investigation. Never blindly erase after an error.
    raise
finally:
    pathlib.Path(output).write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'target': target, 'passed': result.get('passed'), 'tests': result['tests']}))
