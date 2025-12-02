# How to Enable LLM Reasoning

The AutoSec AI system can work in two modes:
1. **RAG-only mode** (default, no API key needed) - Uses template-based explanations
2. **LLM mode** (requires OpenAI API key) - Uses GPT-4 for intelligent reasoning

## Current Status

Your system is running in **RAG-only mode** because:
- `OPENAI_API_KEY` is not set in your environment
- The test script was set to `use_llm=False`

## How to Enable LLM

### Step 1: Get OpenAI API Key

1. Go to https://platform.openai.com/api-keys
2. Sign up or log in
3. Create a new API key
4. Copy the key (starts with `sk-...`)

### Step 2: Set the API Key

**Option A: Create .env file (Recommended)**

```bash
# Create .env file in project root
cd /Users/amruthakanakatteravishankar/Desktop/SEM\ 5/FE524/autosec-ai
echo "OPENAI_API_KEY=sk-your-actual-key-here" > .env
```

**Option B: Set environment variable**

```bash
# In your terminal (temporary - only for current session)
export OPENAI_API_KEY="sk-your-actual-key-here"

# Or add to your ~/.zshrc for permanent setup
echo 'export OPENAI_API_KEY="sk-your-actual-key-here"' >> ~/.zshrc
source ~/.zshrc
```

### Step 3: Verify LLM is Enabled

```bash
# Test the threat intelligence agent
cd backend/agents
python threat_intelligence_agent.py
```

You should see:
```
OPENAI_API_KEY found. LLM will be used for reasoning.
LLM initialized: gpt-4o-mini
```

Instead of:
```
OPENAI_API_KEY not set. Running in RAG-only mode.
Running in RAG-only mode (no LLM reasoning)
```

## What Changes with LLM Enabled?

### RAG-Only Mode (Current)
- Uses template-based explanations
- Faster (no API calls)
- Free (no API costs)
- Less intelligent reasoning

### LLM Mode (With API Key)
- Uses GPT-4 for intelligent analysis
- More accurate threat explanations
- Better context understanding
- Costs money (OpenAI API usage)

## Code Changes

The system automatically detects the API key. You can also explicitly enable/disable:

```python
from backend.agents.threat_intelligence_agent import ThreatIntelligenceAgent
from rag.vector_store.chroma_setup import ThreatIntelligenceRAG

rag = ThreatIntelligenceRAG()

# Enable LLM (if API key is set)
agent = ThreatIntelligenceAgent(rag=rag, use_llm=True)

# Force RAG-only mode
agent = ThreatIntelligenceAgent(rag=rag, use_llm=False)
```

## Cost Considerations

- **Model**: `gpt-4o-mini` (default, cheaper)
- **Cost**: ~$0.15 per 1M input tokens, ~$0.60 per 1M output tokens
- **Typical analysis**: ~500-1000 tokens per threat analysis
- **Estimated cost**: ~$0.001-0.002 per threat analysis

## Troubleshooting

### "OPENAI_API_KEY not found"
- Check that `.env` file exists in project root
- Verify the key is correct (starts with `sk-`)
- Restart your terminal/IDE after setting the key

### "Failed to initialize LLM"
- Check your API key is valid
- Verify you have credits in your OpenAI account
- Check internet connection

### "LangChain not installed"
```bash
pip install langchain langchain-openai
```

## Security Note

**Never commit your `.env` file to git!**

The `.env` file is already in `.gitignore`. Keep your API key secret.



