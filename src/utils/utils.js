export function generateOTP(){
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    return otp;
}

export function getOTPHtml(otp){
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTP Verification</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        .otp {
            font-size: 24px;
            font-weight: bold;
            color: #333;
            margin: 20px 0;
        }
        .message {
            font-size: 16px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Your OTP code</h1>
        <p class="message">Your One-Time Password (OTP) is:</p>
        <div class="otp">${otp}</div>
        <p class="message">Please use this OTP to complete your verification process. This OTP is valid for 10 minutes.</p>
    </div>
</body>
</html>`;
}