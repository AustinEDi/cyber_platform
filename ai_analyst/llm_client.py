import os
import json
import subprocess

def ask_llm(prompt, mode="ollama", model="llama3"):
    """
    Send prompt to the configured LLM backend.
    Supports: ollama, openai, rule-based.
    """
    if mode == "openai":
        import openai
        openai.api_key = os.getenv("OPENAI_API_KEY")
        try:
            resp = openai.ChatCompletion.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2
            )
            return resp.choices[0].message.content
        except Exception as e:
            return f"OpenAI error: {e}"
    elif mode == "ollama":
        try:
            result = subprocess.run(
                ["ollama", "run", model, prompt],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return f"Ollama error: {result.stderr}"
        except FileNotFoundError:
            return "Ollama not installed. Install with: pkg install ollama && ollama pull llama3"
        except Exception as e:
            return f"Ollama error: {e}"
    else:
        return "LLM mode not supported."
