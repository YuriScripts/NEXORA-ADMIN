
export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const data = await request.json();
    const { action, licenseKey, deviceId } = data;

    if (!action || !licenseKey) {
      return Response.json(
        { success: false, message: "Missing required information." },
        { status: 400 }
      );
    }

    const db = env.KV_BINDING;

    if (!db) {
      return Response.json(
        { success: false, message: "License database unavailable." },
        { status: 500 }
      );
    }

    if (action === "activate") {
      const record = await db.get(licenseKey, "json");

      if (!record) {
        return Response.json({
          success: false,
          message: "Invalid license key."
        });
      }

      if (record.status !== "active") {
        return Response.json({
          success: false,
          message: "License is inactive."
        });
      }

      if (record.deviceId && record.deviceId !== deviceId) {
        return Response.json({
          success: false,
          message: "License already activated on another device."
        });
      }

      record.deviceId = deviceId;
      await db.put(licenseKey, JSON.stringify(record));

      return Response.json({
        success: true,
        message: "License activated successfully."
      });
    }

    return Response.json({
      success: false,
      message: "Unknown action."
    }, { status: 400 });

  } catch (error) {
    return Response.json({
      success: false,
      message: "Server error."
    }, { status: 500 });
  }
          }
