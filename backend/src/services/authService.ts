import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { JWT_SECRET, SALT_ROUNDS, TOKEN_EXPIRY } from "../config/config";
import prisma from "../prisma/prismaClient";
import {
  loginSchema,
  registerSchema,
  resetPasswordSchema,
} from "../schemas/authSchema";

export const registerUser = async (data: z.infer<typeof registerSchema>) => {
  const { name, email, password, confirmPassword } = registerSchema.parse(data);

  if (password !== confirmPassword) throw new Error("Passwords do not match");

  const existingUser = await prisma.user.findUnique({ where: { email } });

  if (existingUser) throw new Error("Email already exists");

  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  const user = await prisma.user.create({
    data: { name, email, password: hashedPassword },
  });

  const { password: _, ...userWithoutPassword } = user;
  return userWithoutPassword;
};

export const loginUser = async (data: z.infer<typeof loginSchema>) => {
  const { email, password } = loginSchema.parse(data);

  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) throw new Error("User not found");

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) throw new Error("Invalid password");

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
    expiresIn: TOKEN_EXPIRY,
  });

  const { password: _, ...userWithoutPassword } = user;
  return { user: userWithoutPassword, token };
};

export const resetUserPassword = async (
  userId: string,
  data: z.infer<typeof resetPasswordSchema>
) => {
  const { password, confirmPassword } = resetPasswordSchema.parse(data);

  if (password !== confirmPassword) throw new Error("Passwords do not match");

  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  const user = await prisma.user.update({
    where: { id: userId },
    data: { password: hashedPassword },
  });

  const { password: _, ...userWithoutPassword } = user;
  return userWithoutPassword;
};
