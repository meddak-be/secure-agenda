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

function passwordChecker(password, username, email) {
  let numUpper = 0;
  let numDigits = 0;

  for (let i = 0; i < password.length; i++) {
    if (password[i] >= '0' && password[i] <= '9') {
      numDigits++;
    }
  }

  if (numDigits != password.length && password.length >= 8 &&
      password !== username && password !== email) {
    return true;
  }
  else {
    return false;
  }
}



function submitForm(event) {
    event.preventDefault();
  
    // Get the form data
    const form = event.target;
    const formData = new FormData(form);
    const username = formData.get("username")

    var generateKeys = function (name) {
      //function to generate the private and private keys
      var keySize = parseInt(2048);
      var crypt = new JSEncrypt({ default_key_size: keySize });
      
      crypt.getKey();

      sessionStorage.setItem(name + "PrKey", crypt.getPrivateKey());
      sessionStorage.setItem(name + "PbKey", crypt.getPublicKey());
    };
    
    if (localStorage.getItem(username + "PrKey") == null){
      generateKeys(username);
    }

    let email = formData.get("email").toString();
    let password1 = formData.get("password1").toString();
    let password2 = formData.get("password2").toString();
    
    //check the validity of the user input
    if (passwordChecker(password1, username, email)){
      const hash_psswd1 = CryptoJS.SHA256(formData.get("password1")).toString();
      const hash_psswd2 = CryptoJS.SHA256(formData.get("password2")).toString();
      formData.set("password1", hash_psswd1);
      formData.set("password2", hash_psswd2);
      
      //encrypt and store the private/public key pair (the public key is not uncrypted as it is public)
      const salt = CryptoJS.lib.WordArray.random(128 / 8);
      const key = derive_key(hash_psswd1, salt.toString(), 1000, 256);

      const encryptedPrivKey = CryptoJS.AES.encrypt(sessionStorage.getItem(username+"PrKey"), key);

      localStorage.setItem(username + "PrKey", encryptedPrivKey);
      localStorage.setItem(username + "PbKey", sessionStorage.getItem(username+"PbKey"));
      localStorage.setItem(username + "_salt", salt.toString());
      
      //to store the salt in the database
      const salt_element = document.createElement('input');
      salt_element.type = 'hidden';
      salt_element.name = "salt";
      salt_element.value = salt; 
      form.appendChild(salt_element);
      
      //to store the public key and its signature in the database
      var publicKey = sessionStorage.getItem(username + "PbKey");
      var sign = new JSEncrypt();
      sign.setPrivateKey(sessionStorage.getItem(username + "PrKey"))
      var signedPublicKey = sign.sign(sessionStorage.getItem(username + "PbKey"), CryptoJS.SHA256, "sha256");
  
      const key_element = document.createElement('input');
      key_element.type = 'hidden';
      key_element.name = "key";
      key_element.value = publicKey; 
      form.appendChild(key_element);
  
      const signed_key_element = document.createElement('input');
      signed_key_element.type = 'hidden';
      signed_key_element.name = "signed_key";
      signed_key_element.value = signedPublicKey; 
      form.appendChild(signed_key_element);
  
        // Update the form with the modified form data
        for (const [key, value] of formData.entries()) {
          const input = form.querySelector(`[name="${key}"]`);
          if (input) {
              input.value = value;
          }
      }
  
      // Submit the form
      return form.submit();
    }else{
      alert("Credentials do not meet the minimal requirment. Please try again.")
    }


  }