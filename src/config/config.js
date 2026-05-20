import dotenv from 'dotenv';
dotenv.config();

if(!process.env.MONGO_URI){
    console.error('MONGO_URI is not defined in environment variables');
    process.exit(1);
}
if(!process.env.JWT_SECRET){
    console.error('JWT_SECRET is not defined in environment variables');
    process.exit(1);
}
if(!process.env.GOOGLE_CLIENT_ID){
    console.error('GOOGLE_CLIENT_ID is not defined in environment variables');
    process.exit(1);
}
if(!process.env.GOOGLE_CLIENT_SECRET){
    console.error('GOOGLE_CLIENT_SECRET is not defined in environment variables');
    process.exit(1);
}
if(!process.env.GOOGLE_REFRESH_TOKEN){
    console.error('GOOGLE_REFRESH_TOKEN is not defined in environment variables');
    process.exit(1);
}
if(!process.env.GOOGLE_USER){
    console.error('GOOGLE_USER is not defined in environment variables');
    process.exit(1);
}
const config = {
  PORT: process.env.PORT || 3000,
  MONGO_URI: process.env.MONGO_URI || 'mongodb://localhost:27017/auth_demo',
  JWT_SECRET: process.env.JWT_SECRET,
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
    GOOGLE_REFRESH_TOKEN: process.env.GOOGLE_REFRESH_TOKEN,
    GOOGLE_USER: process.env.GOOGLE_USER,
};

export default config;