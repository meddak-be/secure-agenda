/**Some general functions used in different files */

function encrypt(data, username) {
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey(sessionStorage.getItem(username + "PbKey"));
    var encrypted = encrypt.encrypt(data);
    return encrypted;
}

function decrypt(cipheredData, username){
    var decrypt = new JSEncrypt();
    decrypt.setPrivateKey(sessionStorage.getItem(username + "PrKey"));
    var uncrypted = decrypt.decrypt(cipheredData);
    return uncrypted;
}

function encryptWKey(data, key) {
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey(key);
    var encrypted = encrypt.encrypt(data);
    return encrypted;
}

function decryptWKey(cipheredData, key){
    var decrypt = new JSEncrypt();
    decrypt.setPrivateKey(key);
    var uncrypted = decrypt.decrypt(cipheredData);
    return uncrypted;
}