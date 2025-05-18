import { formSchema } from "@/app/schema";
import arcjet, { detectBot, shield, slidingWindow } from "@arcjet/next";
import { NextRequest, NextResponse } from "next/server";

const aj = arcjet({
  // Get your site key from https://app.arcjet.com
  key: process.env.ARCJET_KEY,
  rules: [
    // Shield protects your app from common attacks e.g. SQL injection
    shield({ mode: "LIVE" }),
    // Create a bot detection rule
    detectBot({
      mode: "LIVE", // Blocks requests. Use "DRY_RUN" to log only
      // Block all bots except the following
      allow: [
        // See the full list at https://arcjet.com/bot-list
        "CATEGORY:SEARCH_ENGINE", // Google, Bing, etc
        "CATEGORY:PREVIEW", // Link previews e.g. Slack, Discord
      ],
    }),
    // Create a token bucket rate limit. Other algorithms are supported.
    slidingWindow({
      mode: "LIVE",
      interval: "10m", // Refill every 10 minutes
      max: 2, // Allow 2 requests per interval
    }),
  ],
});

export async function POST(req: NextRequest) {
  const json = await req.json();
  const data = formSchema.safeParse(json);

  if (!data.success) {
    const { error } = data;

    return NextResponse.json(
      { message: "invalid request", error },
      { status: 400 },
    );
  }

  // The protect method returns a decision object that contains information
  // about the request.
  const decision = await aj.protect(req);

  console.log("Arcjet decision: ", decision);

  if (decision.isDenied()) {
    if (decision.reason.isBot()) {
      return NextResponse.json(
        {
          message: "bots are not allowed.",
          reason: decision.reason,
        },
        { status: 403 },
      );
    } else if (decision.reason.isRateLimit()) {
      return NextResponse.json(
        {
          message: "too many requests. Please try again later.",
          reason: decision.reason,
        },
        { status: 429 },
      );
    } else {
      return NextResponse.json({ message: "Forbidden" }, { status: 403 });
    }
  }

  return NextResponse.json({
    ok: true,
  });
}
