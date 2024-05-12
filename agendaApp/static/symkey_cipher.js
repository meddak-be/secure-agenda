function encryptSymkey(event){
    event.preventDefault();
    // Get the form data
    const form = event.target;
    const formData = new FormData(form);
    //get the friend public key
    pubKey = formData.get("public_key");
    const userLabel = document.getElementById('user_label').value
    const symKeyEncrypted = document.getElementById('sym_key').value;
    const symKeyDec = decrypt(symKeyEncrypted, userLabel)
    const symKey = document.createElement('input');
    symKey.type = 'hidden';
    symKey.name = 'symKey';
    //encryt the symmetric key for the friend and save it to the database
    symKey.value = encryptWKey(symKeyDec, pubKey); 

    form.appendChild(symKey);


    for (const [key, value] of formData.entries()) {
        const input = form.querySelector(`[name="${key}"]`);
        if (input) {
            input.value = value;
        }
      }
    return form.submit();
  }