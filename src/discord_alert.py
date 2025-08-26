import requests
import logging

# Configure logging
logging.basicConfig(
    filename="log/discord_alert.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

with open("log/discord_alert.log",'w') as f:
    pass

DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1409637392708796530/PBfoov4VRJxqTawVc6T4L-L1i7dNfL4Yw8kYvqxKgSqKaXtueTp1m5QVwis4qxoVAX2-"

def send_discord_alert(title, description, extra_info=None):
    """
    Sends an alert message to a Discord channel using a webhook.
    """

    data = {
        "embeds": [
            {
                "title": f"🚨 {title}",
                "description": description,  # (Discord requires lowercase 'description')
                "color": 15158332,  # Red color
                "fields": []
            }
        ]
    }

    if extra_info:
        for key, value in extra_info.items():
            field = {
                "name": key,
                "value": str(value),
                "inline": True
            }
            data["embeds"][0]["fields"].append(field)
            logging.debug(f"Added field to embed: {field}")

    try:
        logging.debug(f"Sending Discord alert: {data}")
        response = requests.post(DISCORD_WEBHOOK, json=data)

        if response.status_code != 204:
            logging.error(f"Failed to send alert - Status: {response.status_code}, Response: {response.text}")
            print("❌ Failed to send alert:", response.text)
        else:
            logging.info(f"Alert sent successfully: {title}")
            print("✅ Alert sent successfully")

    except Exception as e:
        logging.exception(f"Error sending Discord alert: {e}")
        print("❌ Error sending Discord alert:", e)
