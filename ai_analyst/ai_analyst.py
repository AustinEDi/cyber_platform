#!/usr/bin/env python3
"""
AI Analyst – Module 4
Usage:
    python ai_analyst.py ask "Show all ransomware techniques linked to 185.130.5.10 and affected assets"
"""
import sys
import json
import os
from datetime import datetime
from ai_engine import build_context
from llm_client import ask_llm
from countermeasures import get_countermeasure

REPORTS_DIR = "reports"

def format_answer(question, context, llm_response):
    """Return a structured dict with findings, evidence, relationships, confidence."""
    # Simple parsing if LLM returns a structured answer, else return raw.
    # For prototype, we'll attempt to extract sections, else wrap.
    answer = {
        "question": question,
        "findings": llm_response,
        "evidence": [],
        "relationships_used": [],
        "confidence": 70,
        "countermeasures": []
    }
    # If LLM response is empty/error, fill with context
    if not llm_response or "error" in llm_response.lower():
        answer["findings"] = "AI response not available. Using graph context directly."
    # Populate evidence/relationships from context? For now, rely on LLM.
    return answer

def print_answer(answer):
    print("\n" + "=" * 60)
    print("AI ANALYST REPORT")
    print("=" * 60)
    print(f"Question: {answer['question']}")
    print(f"\nFindings:\n{answer['findings']}")
    print(f"\nConfidence: {answer.get('confidence','N/A')}%")
    print("=" * 60)

def save_answer(answer):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    now = datetime.now()
    date_str = now.strftime("%Y%m%d")
    time_str = now.strftime("%H%M%S")
    filename = f"ai_report_{date_str}-{time_str}.txt"
    path = os.path.join(REPORTS_DIR, filename)
    with open(path, "w") as f:
        f.write(f"Question: {answer['question']}\n")
        f.write(f"Findings: {answer['findings']}\n")
        f.write(f"Confidence: {answer.get('confidence','N/A')}%\n")
    print(f"\n[+] Report saved to {path}")

def main():
    if len(sys.argv) < 3 or sys.argv[1] != "ask":
        print("Usage: python ai_analyst.py ask \"<question>\"")
        print("Example: python ai_analyst.py ask \"What malware is associated with 185.130.5.10?\"")
        sys.exit(1)

    question = sys.argv[2]
    print("[*] Gathering graph context...")
    context, nodes, edges = build_context(question)
    if not nodes:
        print("[-] No graph data found for this query. Make sure data is ingested.")
        sys.exit(1)

    # Build prompt
    prompt = f"""You are a cybersecurity analyst assistant. Based on the graph context below, answer the following question.
Provide findings, evidence (specific nodes/edges), relationships used, and a confidence score (0-100%).
Also suggest countermeasures if relevant.

Question: {question}

Graph context:
{context}

Answer in the following format:
Findings: <text>
Evidence: <text>
Relationships Used: <text>
Confidence: <number>%
Countermeasures: <text>"""

    print("[*] Asking AI...")
    response = ask_llm(prompt, mode="ollama", model="llama3")
    # Fallback to rule-based if ollama unavailable
    if "not installed" in response.lower() or "error" in response.lower():
        print("[!] Ollama unavailable, using rule-based fallback.")
        # Rule-based: simple summary from context
        findings = "No AI available. Graph context shows " + str(len(nodes)) + " nodes and " + str(len(edges)) + " edges."
        response = f"Findings: {findings}\nEvidence: See graph\nRelationships Used: See graph\nConfidence: 50%\nCountermeasures: None"

    answer = format_answer(question, context, response)
    print_answer(answer)
    save_answer(answer)

if __name__ == "__main__":
    main()
