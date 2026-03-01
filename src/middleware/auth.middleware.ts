import { Request, Response, NextFunction } from "express";
import { AuthUtils } from "../utils";
import { IUserDoc, IUserModel } from "../types";

export interface AuthRequest extends Request {
  user?: IUserDoc;
}

export class AuthMiddleware {
  private authUtils: AuthUtils;
  private userModel: IUserModel;

  constructor(authUtils: AuthUtils, userModel: IUserModel) {
    this.authUtils = authUtils;
    this.userModel = userModel;
  }

  // JWT Authentication middleware
  authenticate = async (
    req: AuthRequest,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      if (!!req.user) {
        return next();
      }

      const authHeader = req.headers.authorization;
      const token = AuthUtils.extractTokenFromHeader(authHeader || "");

      if (!token) {
        res.status(401).json({ error: "Access token required" });
        return;
      }

      const decoded = this.authUtils.verifyToken(token);
      const user = await this.userModel.findById(decoded.userId);

      if (!user || !user.isActive) {
        res.status(401).json({ error: "Invalid or inactive user" });
        return;
      }

      req.user = user;
      next();
    } catch (error) {
      res.status(401).json({ error: "Invalid or expired token" });
    }
  };

  // Optional authentication middleware (doesn't fail if no token)
  parseAuthTokenSoftly = async (
    req: AuthRequest,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;
      const token = AuthUtils.extractTokenFromHeader(authHeader || "");

      if (token) {
        const decoded = this.authUtils.verifyToken(token);
        const user = await this.userModel.findById(decoded.userId);

        if (user && user.isActive) {
          req.user = user;
        }
      }

      next();
    } catch (error) {
      // Continue without authentication
      next();
    }
  };

  // Role-based authorization middleware
  // authorize = (roles: string[]) => {
  //   return (req: AuthRequest, res: Response, next: NextFunction): void => {
  //     if (!req.user) {
  //       res.status(401).json({ error: 'Authentication required' });
  //       return;
  //     }

  //     // Check if user has any of the required roles
  //     const userRoles = req.user.roles || [];
  //     const hasPermission = roles.some(role => userRoles.includes(role));

  //     if (!hasPermission) {
  //       res.status(403).json({ error: 'Insufficient permissions' });
  //       return;
  //     }

  //     next();
  //   };
  // };

  requireVerifiedEmail = (
    req: AuthRequest,
    res: Response,
    next: NextFunction,
  ): void => {
    if (!req.user) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    if (!req.user.isVerified) {
      res.status(403).json({ error: "Email verification required" });
      return;
    }

    next();
  };
}

export const createAuthMiddleware = (
  authUtils: AuthUtils,
  userModel: IUserModel,
): AuthMiddleware => {
  return new AuthMiddleware(authUtils, userModel);
};
