import nodemailer from 'nodemailer';
import config from '../config/config.js';

const transporter = nodemailer.createTransport(
    {
        service: 'gmail',
        auth:{
            type: 'OAuth2',
            user: config.GOOGLE_USER,
            clientId: config.GOOGLE_CLIENT_ID,
            clientSecret: config.GOOGLE_CLIENT_SECRET,
            refreshToken: config.GOOGLE_REFRESH_TOKEN
        }
    }
)

//verify the connection configuration
transporter.verify((error, success) => {
    if(error){
        console.error('Error configuring email transporter:', error);
    }else{
        console.log('Email transporter is ready to send messages');
    }
})

// Send email function
export const sendEmail = async (to, subject, text, html = null) => { // 1. Added html parameter with a default value of null
    try {
        const mailOptions = {
            from: `Your name <${config.GOOGLE_USER || config.EMAIL_USER}>`, // 2. Fixed syntax from $(...) to ${...}
            to,       // receiver address
            subject,  // email subject
            text,     // email body (plain text)
        };

        // 3. Only attach html format if it was explicitly provided to the function
        if (html) {
            mailOptions.html = html; 
        }

        await transporter.sendMail(mailOptions);
        console.log(`Email successfully sent to ${to}`);
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
}

