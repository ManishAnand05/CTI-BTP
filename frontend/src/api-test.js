import { api } from "./api.js";

async function testConnection() {
  try {
    const result = await api.getAdvancedCTI();

    console.log("Backend connection successful!");
    console.log("Advanced CTI response:", result);
  } catch (error) {
    console.error("Backend connection failed:", error.message);
  }
}

testConnection();