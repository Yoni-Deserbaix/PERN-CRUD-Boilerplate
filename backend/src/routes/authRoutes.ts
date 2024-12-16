import express from "express";
import {
  getCurrentUser,
  login,
  logout,
  register,
  resetPassword,
} from "../controllers/authController";
import authMiddleware from "../middlewares/authMiddleware";

const router = express.Router();

router.post("/auth/register", register);
router.post("/auth/login", login);
router.get("/auth/current-user", authMiddleware, getCurrentUser);
router.post("/auth/reset-password", authMiddleware, resetPassword);
router.post("/auth/logout", logout);

export default router;
