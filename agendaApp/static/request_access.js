function submitForm(event) {
    event.preventDefault();

    const form = event.target;

    //generate a temporary symmetric key for the access request
    const keyObj = CryptoJS.lib.WordArray.random(32);
    symKey = keyObj.toString(CryptoJS.enc.Hex);

    localStorage.setItem("tmp_sym", symKey);

    let user_label = document.getElementById('user');
    let username = user_label.dataset.username;
    let public_key = user_label.dataset.publickey;

    const keyField = document.createElement('input');
    keyField.type = 'hidden';
    keyField.name = 'tmp_key';
    keyField.value = encryptWKey(symKey, public_key); // encrypt symmetric key using the "old device"'s public key
    form.appendChild(keyField); // transmit the encrypted symmetric key to the serve
    
    
    return form.submit();
}