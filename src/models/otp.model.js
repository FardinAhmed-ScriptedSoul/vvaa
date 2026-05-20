import mongoose from "mongoose";

const otpSchema = new mongoose.Schema
(
    {
        email:{
            type:String,
            required:[true,"Email is required"],
            match:[/\S+@\S+\.\S+/, 'Please use a valid email address']
        },
        user:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"User",
            required:[true,"User is required"]
        },
        otpHash:{
            type:String,
            required:[true,"OTP hash is required"]
        }
    },
    {
        timestamps:true
    }
)

const otpModel = mongoose.model('OTP', otpSchema);

export default otpModel;