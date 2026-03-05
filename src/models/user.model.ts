import mongoose, { Schema, SchemaDefinition, model } from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import {
  IUserDoc,
  EmailPasswordData,
  userRegistrationSchema,
  userLoginSchema,
  UserLoginData,
  IUserModel,
} from "../types";
import { Profile } from "passport-google-oauth20";

const schemaObj: SchemaDefinition<IUserDoc> = {
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true,
  },
  password: {
    type: String,
    select: false,
  },
  role: String,
  oAuthStrategies: {
    type: [
      {
        provider: {
          type: String,
          required: true,
          enum: ["google", "facebook", "github", "twitter", "linkedin"],
        },
        id: {
          type: String,
          required: true,
        },
        accessToken: String,
        refreshToken: String,
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    select: false,
  },
  fullName: {
    type: String,
    trim: true,
  },

  avatar: {
    type: String,
  },
  bio: String,
  phone: String,
  isActive: {
    type: Boolean,
    default: true,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  isEmailVerified: {
    type: Boolean,
    default: false,
  },
  otp: {
    type: String,
    select: false,
  },
  lastLogin: {
    type: Date,
  },
};

// Enhanced function to create User model with additional fields
export function createUserModel<T extends SchemaDefinition>(
  additionalFields?: T,
  options?: { modelName?: string; mongooseConnection?: mongoose.Connection },
) {
  const { modelName = "User", mongooseConnection } = options || {};
  type DataType = mongoose.InferRawDocType<T> & IUserDoc;
  const conflictingFields = Object.keys(additionalFields || {}).filter((key) =>
    Object.keys(schemaObj).includes(key),
  );

  if (conflictingFields.length > 0) {
    throw new Error(
      `Additional fields conflict with existing schema fields: ${conflictingFields.join(
        ", ",
      )}`,
    );
  }

  const schema = assignMethods(
    new Schema<DataType>(
      {
        ...additionalFields,
        ...schemaObj,
      },
      {
        timestamps: true,
      },
    ),
  );

  if (mongooseConnection) {
    return mongooseConnection.model<DataType>(
      modelName,
      schema,
    ) as IUserModel<DataType>;
  }

  return model<DataType>(modelName, schema) as IUserModel<DataType>;
}

function assignMethods<T extends Schema>(defaultUserSchema: T): T {
  // Pre-save middleware to hash password
  defaultUserSchema.pre("save", async function (this) {
    if (!this.isModified("password") || typeof this.password !== "string")
      return;

    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
  });

  defaultUserSchema.methods.comparePassword = async function (
    candidatePassword: string,
  ): Promise<boolean> {
    if (!this.password) return false;
    return bcrypt.compare(candidatePassword, this.password);
  };

  defaultUserSchema.methods.generateAuthToken = function (): string {
    const payload = {
      userId: this._id.toString(),
      email: this.email,
    };

    const secret = process.env.JWT_SECRET || "default-secret";
    return jwt.sign(payload, secret, { expiresIn: "24h" });
  };

  defaultUserSchema.statics.findByEmail = function (email: string) {
    return this.findOne({ email }).select("+password");
  };

  defaultUserSchema.statics.findByOAuthId = function (
    provider: string,
    oAuthId: string,
  ) {
    return this.findOne({
      "oAuthStrategies.provider": provider,
      "oAuthStrategies.id": oAuthId,
    });
  };

  // Static method to create user with OAuth profile
  defaultUserSchema.statics.createWithOAuth = async function (
    provider: string,
    profile: Profile,
    tokens?: { accessToken?: string; refreshToken?: string },
  ) {
    const userData = {
      email: profile.emails?.[0]?.value,
      oAuthStrategies: [
        {
          provider,
          id: profile.id,
          accessToken: tokens?.accessToken,
          refreshToken: tokens?.refreshToken,
        },
      ],
      fullName: profile.displayName,
      avatar: profile.photos?.[0]?.value,
      isEmailVerified: profile.emails?.[0]?.verified || false,
    };

    return this.create(userData);
  };

  defaultUserSchema.statics.createWithEmailPassword = async function (
    data: EmailPasswordData,
  ) {
    const validatedData = userRegistrationSchema.parse(data);
    return this.create(validatedData);
  };

  // Static method to validate login credentials
  defaultUserSchema.statics.validateLoginCredentials = function (
    data: any,
  ): UserLoginData {
    return userLoginSchema.parse(data);
  };

  return defaultUserSchema;
}
