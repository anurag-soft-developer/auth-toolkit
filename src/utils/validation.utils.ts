import { z } from "zod";
import { userRegistrationSchema } from "../types";

export class ValidationUtils {
  /**
   * Create a validation error response
   * @param error - Zod validation error
   * @returns Formatted error response
   */
  static formatValidationError(error: z.ZodError): {
    message: string;
    errors: Array<{
      field: string;
      message: string;
    }>;
  } {
    return {
      message: "Validation failed",
      errors: error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      })),
    };
  }

  /**
   * Create extended validation schema for custom user models
   * @param additionalFields - Additional Zod schema fields
   * @returns Extended registration schema
   */
  static createExtendedRegistrationSchema<
    T extends Record<string, z.ZodTypeAny>,
  >(additionalFields: T) {
    return userRegistrationSchema.extend(additionalFields);
  }
}

export const commonPatterns = {
  strongPassword: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password too long")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/\d/, "Password must contain at least one number")
    .regex(
      /[!@#$%^&*(),.?":{}|<>]/,
      "Password must contain at least one special character",
    ),

  phoneNumber: z
    .string()
    .regex(/^\+?[1-9]\d{1,14}$/, "Invalid phone number format"),

  imageUrl: z
    .string()
    .url("Invalid URL format")
    .regex(/\.(jpg|jpeg|png|gif|webp)(\?.*)?$/i, "Must be a valid image URL"),

  username: z
    .string()
    .min(3, "Username must be at least 3 characters")
    .max(30, "Username too long")
    .regex(
      /^[a-zA-Z0-9_]+$/,
      "Username can only contain letters, numbers, and underscores",
    ),
};
