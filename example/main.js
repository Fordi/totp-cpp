import init from "../totp.js";
const { TOTP } = await init();

const totp = TOTP.from_url("otpauth://totp/login-patient.labcorp.com?secret=XFL6GIJQIFSMCKHR&issuer=login-patient.labcorp.com");
console.log(totp.code());
