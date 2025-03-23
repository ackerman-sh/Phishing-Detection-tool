from flask import Flask, render_template, request, Response, jsonify
import requests
import json
import time
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential
from azure.ai.inference.models import UserMessage

app = Flask(__name__)

def load_api_key(key_name):
    try:
        with open("api.json", "r") as file:
            data = json.load(file)
            return data.get(key_name)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"⚠️ Warning: Could not load {key_name} - {str(e)}")
        return None

# Load API keys
VIRUSTOTAL_TOKEN = load_api_key("VIRUSTOTAL_API_KEY")
GITHUB_TOKEN = load_api_key("GITHUB_API_KEY")

if not GITHUB_TOKEN:
    raise ValueError("❌ GITHUB_TOKEN is missing in api.json!")
if not VIRUSTOTAL_TOKEN:
    raise ValueError("❌ VIRUSTOTAL_API_KEY is missing in api.json!")

try:
    client = ChatCompletionsClient(endpoint="https://models.inference.ai.azure.com",credential=AzureKeyCredential(GITHUB_TOKEN))
except Exception as e:
    print(f"⚠️ Error initializing AI client: {str(e)}")
    client = None

def scan_url(url):
    global Virus_total_report

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_TOKEN, "Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(vt_url, headers=headers, data=f"url={url}", timeout=10)
        response.raise_for_status()
        analysis_id = response.json().get("data", {}).get("id")

        if not analysis_id:
            return {"error": "Failed to retrieve analysis ID from VirusTotal."}

        Virus_total_report = get_url_report(analysis_id)
        return Virus_total_report

    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal API request failed: {str(e)}"}

def get_url_report(analysis_id):
    vt_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VIRUSTOTAL_TOKEN}

    retries = 5  # Max retries before giving up
    for attempt in range(retries):
        try:
            response = requests.get(vt_url, headers=headers, timeout=10)
            response.raise_for_status()

            report = response.json()
            status = report.get("data", {}).get("attributes", {}).get("status")

            if status == "completed":
                results = report["data"]["attributes"]["stats"]
                return {**results, "raw_report": report}
            
            time.sleep(2)
        except requests.exceptions.RequestException as e:
            return {"error": f"Failed to fetch VirusTotal report: {str(e)}"}

    return {"error": "VirusTotal scan did not complete in time."}

@app.route("/scan_url", methods=["POST"])
def scan_url_endpoint():
    try:
        data = request.json
        url = data.get("url", "").strip()

        if not url:
            return jsonify({"error": "URL is required."}), 400

        return jsonify(scan_url(url))
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

@app.route("/get_ai_report", methods=["POST"])
def get_ai_report():
    global Virus_total_report

    if not Virus_total_report:
        return jsonify({"error": "Scan data is empty. Provide valid input."}), 400

    user_query = f"Evaluate this VirusTotal Report shortly and delve into the conclusion:\n{Virus_total_report}"

    def generate_response():
        yield "Initializing GitHub AI Chat Client...\n\n"

        if not client:
            yield "❌ AI Client initialization failed. Check your API credentials.\n\n"
            return

        yield "✅ Successfully authenticated with GitHub AI endpoint\n\n"
        yield "📩 Sending query to DeepSeek-R1 model...\n\n"
        yield "⌛ Please wait... Fetching AI analysis...\n\n"

        start_time = time.time()

        try:
            response = client.complete(
                messages=[UserMessage(user_query)],
                model="DeepSeek-R1",
                max_tokens=2048,
                temperature=0.7
            )

            elapsed_time = time.time() - start_time

            yield f"⏱️ Response received in {elapsed_time:.2f} seconds\n\n"
            yield "📝 Response content:\n==================================================\n\n"
            for chunk in response.choices[0].message.content.split("\n"):
                yield f"{chunk}\n\n"
                time.sleep(0.1)

            yield "==================================================\n\n"
            yield "✅ AI Analysis Complete!\n\n"

        except Exception as e:
            yield f"🔥 Error: {str(e)}\n\n"
            yield "⚠️ Troubleshooting tips:\n - Verify your GITHUB_TOKEN is valid\n - Check network connectivity\n - Ensure the DeepSeek-R1 model is available in your region\n\n"
            print(f"🔥 Critical error occurred: {str(e)}")

    return Response(generate_response(), mimetype="text/event-stream")

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
