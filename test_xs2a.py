from main import run, psd2_client_certs


def test_xs2a_download():
    begin_cert = '-----BEGIN CERTIFICATE-----\n'
    end_cert = '-----END CERTIFICATE-----\n'

    run()
    with open(psd2_client_certs, 'r') as ca_handler:
        lines = ca_handler.readlines()

    assert begin_cert == lines[0]
    assert end_cert == lines[len(lines) - 1]

    begin_cnt = 0
    end_cnt = 0
    for line in lines:
        if line == begin_cert:
            begin_cnt = begin_cnt+1
        elif line == end_cert:
            end_cnt = end_cnt+1

    assert begin_cnt > 50
    assert begin_cnt == end_cnt
