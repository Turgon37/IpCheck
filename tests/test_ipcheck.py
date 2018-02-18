import ipcheck

def test_without_url():
    """Must produce an error is no url was given"""
    program = ipcheck.IpCheck()
    assert program.start() == 3

def test_with_bad_tmp_directory_path_in_stdout(capsys):
    """Must produce an error is the temporary directory cannot be created"""
    program = ipcheck.IpCheck()
    program.configure(urls_v4=['http://8.8.8.8/'], tmp_directory='/impossible/path')
    assert program.start() == 1
    out, err = capsys.readouterr()
    assert 'Unable to create the required directory' in out

def test_with_bad_tmp_directory_path_in_stderr(capsys):
    """Must produce an error is the temporary directory cannot be created"""
    program = ipcheck.IpCheck()
    program.configure(urls_v4=['http://8.8.8.8/'],
                        tmp_directory='/impossible/path',
                        verbose=-1,
                        errors_to_stderr=True,
                        )
    assert program.start() == 1
    out, err = capsys.readouterr()
    assert 'Unable to create the required directory' in err
