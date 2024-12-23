from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof

import sys

if __name__ == '__main__':
    if (len(sys.argv) > 1):
        peggy_pwd = str(sys.argv[1])
    else:
        peggy_pwd = "Test 456"
    if (len(sys.argv) > 2):
        victor_pwd = str(sys.argv[2])
    else:
        victor_pwd = "Test 123"

    peggy_zk = ZK.new(curve_name="secp256k1", hash_alg="sha3_256")
    peggy_sig = peggy_zk.create_signature(peggy_pwd)
    print("Peggy signature = ", peggy_sig)
    peggy_signature = ZKSignature.load(peggy_sig.dump())
    peggy_zk = ZK(peggy_signature.params)
    print("Peggy ZK's token = ", peggy_zk.token())

    victor_zk = ZK.new(curve_name="secp384r1", hash_alg="sha3_512")
    victor_sig = victor_zk.create_signature(victor_pwd)
    print("Victor signature = ", victor_sig)
    token = victor_zk.sign(victor_pwd, peggy_zk.token())
    proof = peggy_zk.sign(peggy_pwd, token).dump()

    print("Peggy password: ", peggy_pwd)
    print("Victor password: ", victor_pwd)
    print("\nToken: ", token)
    print("\nProof: ", proof)

    proof = ZKData.load(proof)

    if not victor_zk.verify(token, victor_sig):
        print("\nNo Success")
    else:
        print("\nSuccess")

