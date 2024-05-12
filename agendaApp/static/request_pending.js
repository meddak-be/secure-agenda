function addPrivatePublicKeys() {

    let info_label = document.getElementById('infos');
    let access = info_label.dataset.access;
    let username = info_label.dataset.username;
    if (access == "accepted"){
        let public_key = info_label.dataset.public;
        let enc_private_key = info_label.dataset.private;
        let salt = info_label.dataset.salt;


        let private_key = CryptoJS.AES.decrypt(enc_private_key, localStorage.getItem("tmp_sym")); // decrypt the private key with the symmetric key
        private_key = private_key.toString(CryptoJS.enc.Utf8);

        localStorage.removeItem("tmp_sym")

        localStorage.setItem(username + "PrKey", private_key); // store the keys and salt (private key is already encrypted with the password derivation)
        localStorage.setItem(username + "PbKey", public_key);
        localStorage.setItem(username + "_salt", salt);
    }

}

addPrivatePublicKeys();