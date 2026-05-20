import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema(
    {
        user:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"User",
            required:[true,"User is required"]
        },
        refreshToken:{
            type:String,
            required:[true,"Refresh token is required"]
        },
        ip:{
            type:String,
            required:[true,"IP address is required"]
        },
        userAgent:{ //info about the device and browser used for login
            type:String,
            required:[true,"User agent is required"]
        },
        revoked:{ //if the session is revoked (e.g. user logged out or token is compromised)
            type:Boolean,
            default:false
        }
    },
    {
        timestamps:true
    }
)

const sessionModel = mongoose.model('Session', sessionSchema);

export default sessionModel;