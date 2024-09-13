import Encryption from './Encryption';

const ciphertext = 'f78D2XXh8tnSc8a5/FE=:0LDv4U8TeV918C/NvPLOpA==';
const encryptionKey = 'risk3sixty';

const encryption = Encryption(encryptionKey);
const decryptedText = encryption.decrypt(ciphertext);

console.log(decryptedText); // should print out r3s is m00ning