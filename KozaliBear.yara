rule KozaliBear_Ransomware {
    meta:
        description = "KozaliBear ransomware"
        author = "Filippos Fouskas"
    strings:
        $library_hash1 = "85578cd4404c6d586cd0ae1b36c98aca"
        $library_hash2 = "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849"
        $bitcoin_wallet = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6"
        $virus_signature = { 98 1d 00 00 ec 33 ff ff fb 06 00 00 00 46 0e 10 }
    condition:
        any of ($library_hash1, $library_hash2) or
        $bitcoin_wallet or
        $virus_signature
}
