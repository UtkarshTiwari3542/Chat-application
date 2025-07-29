import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute = async (req, res, next) => {
    try {
        const token = req.cookies.jwt;

        if (!token) {
            return res.status(401).json({ message: "Unauthorized - No token provided" });
        }

        const secretKey = process.env.JWT_SECRET;

        if (!secretKey) {
            console.error("JWT_SECRET is not defined in environment variables");
            return res.status(500).json({ message: "Server misconfiguration - Missing JWT_SECRET" });
        }

        const decoded = jwt.verify(token, secretKey);

        const user = await User.findById(decoded.userId).select("-password");

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        req.user = user;
        next();

    } catch (error) {
        console.error("Error in protectRoute middleware:", error.message);
        return res.status(401).json({ message: "Unauthorized - Invalid or expired token" });
    }
};
