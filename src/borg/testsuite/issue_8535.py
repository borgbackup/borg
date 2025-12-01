import os
import pytest
from borg.constants import *  # noqa: F403
from borg.helpers import msgpack
from borg.testsuite.archiver import exec_cmd


@pytest.fixture
def borg_env(tmp_path, monkeypatch):
    monkeypatch.setenv('BORG_CHECK_I_KNOW_WHAT_I_AM_DOING', 'YES')
    monkeypatch.setenv('BORG_DELETE_I_KNOW_WHAT_I_AM_DOING', 'YES')
    monkeypatch.setenv('BORG_PASSPHRASE', 'waytooeasyonlyfortests')
    monkeypatch.setenv('BORG_SELFTEST', 'disabled')

    # Set up directories
    keys_path = tmp_path / 'keys'
    cache_path = tmp_path / 'cache'
    input_path = tmp_path / 'input'

    monkeypatch.setenv('BORG_KEYS_DIR', str(keys_path))
    monkeypatch.setenv('BORG_CACHE_DIR', str(cache_path))

    keys_path.mkdir()
    cache_path.mkdir()
    input_path.mkdir()

    # Create test file
    (input_path / 'file1').write_bytes(b'X' * 1024 * 80)

    cwd = os.getcwd()
    os.chdir(tmp_path)
    yield {
        'repo': str(tmp_path / 'repository'),
        'input': str(input_path),
    }
    os.chdir(cwd)


def cmd(*args, **kw):
    kw.setdefault('fork', True)
    ret, output = exec_cmd(*args, **kw)
    if ret != 0:
        print(output)
    assert ret == 0
    return output


def test_missing_segment_in_hints(borg_env):
    """Test that compact handles missing segment files gracefully."""
    repo = borg_env['repo']

    cmd('init', '--encryption=none', repo)
    cmd('create', repo + '::archive1', 'input')
    cmd('delete', repo + '::archive1')

    # Find hints
    hints_files = sorted([f for f in os.listdir(repo) if f.startswith('hints.') and not f.endswith('.tmp')],
                         key=lambda x: int(x.split('.')[1]))
    hints_file = os.path.join(repo, hints_files[-1])

    with open(hints_file, 'rb') as f:
        hints = msgpack.unpack(f)

    # Find data segment
    target_segment = None
    for seg in hints[b'compact'].keys():
        segment_file = os.path.join(repo, 'data', str(seg // 10000), str(seg))
        if os.path.exists(segment_file) and os.path.getsize(segment_file) > 100:
            target_segment = seg
            break

    assert target_segment is not None

    # Delete segment file
    segment_file = os.path.join(repo, 'data', str(target_segment // 10000), str(target_segment))
    os.unlink(segment_file)

    # Compact should succeed
    cmd('compact', repo)

    # Verify hints updated
    hints_files = sorted([f for f in os.listdir(repo) if f.startswith('hints.') and not f.endswith('.tmp')],
                         key=lambda x: int(x.split('.')[1]))
    new_hints_file = os.path.join(repo, hints_files[-1])

    with open(new_hints_file, 'rb') as f:
        new_hints = msgpack.unpack(f)

    assert target_segment not in new_hints[b'compact']
    assert target_segment not in new_hints[b'segments']


def test_index_corruption_with_old_hints(borg_env):
    """Test that compact handles corrupted index (with old hints) gracefully."""
    repo = borg_env['repo']

    cmd('init', '--encryption=none', repo)
    cmd('create', repo + '::archive1', 'input')

    # Corrupt index
    index_files = sorted([f for f in os.listdir(repo) if f.startswith('index.') and not f.endswith('.tmp')],
                         key=lambda x: int(x.split('.')[1]))
    index_path = os.path.join(repo, index_files[-1])

    with open(index_path, 'wb') as f:
        f.write(b'corrupted')

    # Compact should succeed (with fix)
    cmd('compact', repo)
