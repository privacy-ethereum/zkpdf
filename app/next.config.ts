import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  basePath: process.env.NODE_ENV === "production" ? "/zkpdf" : "",
  assetPrefix: process.env.NODE_ENV === "production" ? "/zkpdf/" : "",
};

export default nextConfig;
