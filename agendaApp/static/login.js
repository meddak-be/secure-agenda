function derive_key (secret, salt, iterations, keylen) {
  //generate a key based on the parameter (PBKFD2 method)
  var iterations = iterations;
  var keylen = keylen;
  var config = {
     keySize: keylen / 32,
     iterations: iterations,
     hasher: CryptoJS.algo.SHA256
  }
  var key = CryptoJS.PBKDF2(secret, salt, config);
  return key.toString(CryptoJS.enc.Base64);
}

function submitForm(event) {
    event.preventDefault();
  
    // Get the form data
    const form = event.target;
    const formData = new FormData(form);
    const username = formData.get("username");
    //hash the password
    const hash = CryptoJS.SHA256(formData.get("password")).toString();
    formData.set("password", hash);
    if (localStorage.getItem(username + "PbKey") != null){
      const key = derive_key(hash, localStorage.getItem(username + "_salt"), 1000, 256);
      const decryptedPrKey = CryptoJS.AES.decrypt(localStorage.getItem(username + "PrKey"), key);
      //store the public and private key in the session storage
      sessionStorage.setItem(username + "PbKey", localStorage.getItem(username + "PbKey"))
      sessionStorage.setItem(username + "PrKey", decryptedPrKey.toString(CryptoJS.enc.Utf8))
    }
    // Update the form with the modified form data
    for (const [key, value] of formData.entries()) {
      const input = form.querySelector(`[name="${key}"]`);
      if (input) {
          input.value = value;
      }
    }

    // Submit the form
    return form.submit();
  }