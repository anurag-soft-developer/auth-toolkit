import jwt from 'jsonwebtoken';
import validator from 'validator';
import { JWTPayload } from '../types';
import { commonPatterns } from './validation.utils';

export class AuthUtils {
  private jwtSecret: string;
  private jwtExpiresIn: string;

  constructor(jwtSecret: string, jwtExpiresIn: string = '24h') {
    this.jwtSecret = jwtSecret;
    this.jwtExpiresIn = jwtExpiresIn;
  }

  generateToken(payload: Omit<JWTPayload, 'iat' | 'exp'>): string {
    return jwt.sign(payload, this.jwtSecret, { expiresIn: this.jwtExpiresIn } as jwt.SignOptions);
  }

  verifyToken(token: string): JWTPayload {
    return jwt.verify(token, this.jwtSecret) as JWTPayload;
  }

  // Decode JWT token without verification (useful for expired token info)
  decodeToken(token: string): JWTPayload | null {
    try {
      return jwt.decode(token) as JWTPayload;
    } catch {
      return null;
    }
  }

  // Validate email
  static validateEmail(email: string): boolean {
    return validator.isEmail(email);
  }

  static validatePassword(password: string): {
    isValid: boolean;
    errors: string[];
  } {

    const result = commonPatterns.strongPassword.safeParse(password);
    
    if (result.success) {
      return {
        isValid: true,
        errors: []
      };
    }
    
    return {
      isValid: false,
      errors: result.error.issues.map(issue => issue.message)
    };
  }

  // Sanitize user data for response (remove sensitive fields)
  static sanitizeUser(user: any): any {
    const sanitized = { ...user };
    delete sanitized.password;
    delete sanitized.__v;
    
    if (sanitized._id) {
      sanitized.id = sanitized._id;
    }
    
    return sanitized;
  }

  // Generate random string
  static generateRandomString(length: number = 32): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  // Extract token from Authorization header
  static extractTokenFromHeader(authHeader: string): string | null {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.substring(7);
  }
}

// Export utility functions as standalone
export const validateEmail = AuthUtils.validateEmail;
export const validatePassword = AuthUtils.validatePassword;
export const sanitizeUser = AuthUtils.sanitizeUser;
export const generateRandomString = AuthUtils.generateRandomString;
export const extractTokenFromHeader = AuthUtils.extractTokenFromHeader;