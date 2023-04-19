const nodemailer = require("nodemailer");

const sendEmail=async({from,to,subject,msg})=>{
    let testAccount = await nodemailer.createTestAccount();
    const transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      auth: {
        user: 'hobart.gusikowski56@ethereal.email',
        pass: 'GsvvQ58qPFBGjRfweH'
      },
/*let transporter = nodemailer.createTransport({
  host: "smtp.ethereal.email",
  port: 587,
  secure: false,
  auth: {
      user: 'jana.halvorson@ethereal.email',
      pass: 'cxRbyUA6vCzqKBN4DB'
  },*/
  tls : { rejectUnauthorized: false }
});
  await transporter.sendMail({
  from,to,subject,html:msg
})
}
module.exports=sendEmail