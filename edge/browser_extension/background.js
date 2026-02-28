const API_URL = 'http://localhost:8000';
const EDGE_THRESHOLD_BLOCK = 0.90;
const EDGE_THRESHOLD_ALLOW = 0.10;

let urlnetSession = null;
let distilbertSession = null;

async function loadEdgeModels() {
  try {
    if (typeof ort !== 'undefined' && ort.InferenceSession) {
      urlnetSession = await ort.InferenceSession.create('./models/urlnet_int8.onnx');
      distilbertSession = await ort.InferenceSession.create('./models/distilbert_int8.onnx');
      console.log('Edge ONNX models loaded');
    } else {
      console.log('ORT runtime unavailable, fallback heuristic mode enabled');
    }
  } catch (error) {
    console.error('Failed to load edge models:', error);
  }
}

function tokenizeCharacters(url) {
  const maxLen = 200;
  const out = new BigInt64Array(maxLen);
  for (let i = 0; i < Math.min(url.length, maxLen); i++) {
    out[i] = BigInt(url.charCodeAt(i) % 128);
  }
  return out;
}

function tokenizeWords(url) {
  const maxLen = 30;
  const out = new BigInt64Array(maxLen);
  const words = url.split(/[./\-_?=&]/).filter(Boolean);
  for (let i = 0; i < Math.min(words.length, maxLen); i++) {
    let hash = 0;
    for (const ch of words[i]) {
      hash = ((hash << 5) - hash) + ch.charCodeAt(0);
      hash |= 0;
    }
    out[i] = BigInt(Math.abs(hash % 50000));
  }
  return out;
}

function heuristicScore(url) {
  const patterns = ['paypa1', 'g00gle', 'amaz0n', 'micr0soft'];
  const hasSuspicious = patterns.some((p) => url.toLowerCase().includes(p));
  return hasSuspicious ? 0.88 : 0.18;
}

async function analyzeURLEdge(url) {
  if (!urlnetSession || typeof ort === 'undefined' || !ort.Tensor) {
    return { score: heuristicScore(url), source: 'edge_heuristic' };
  }

  try {
    const charInput = tokenizeCharacters(url);
    const wordInput = tokenizeWords(url);

    const charTensor = new ort.Tensor('int64', charInput, [1, 200]);
    const wordTensor = new ort.Tensor('int64', wordInput, [1, 30]);

    const outputs = await urlnetSession.run({
      char_input: charTensor,
      word_input: wordTensor,
    });

    const key = Object.keys(outputs)[0];
    const score = Number(outputs[key].data[0]);
    return { score: isNaN(score) ? heuristicScore(url) : score, source: 'edge' };
  } catch (error) {
    console.error('Edge inference failed:', error);
    return { score: heuristicScore(url), source: 'edge_fallback' };
  }
}

async function analyzeURLCloud(url) {
  try {
    const response = await fetch(`${API_URL}/api/v2/analyze/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer demo_token'
      },
      body: JSON.stringify({
        url,
        follow_redirects: true,
        context: 'web'
      })
    });
    if (response.ok) {
      return await response.json();
    }
  } catch (error) {
    console.error('Cloud analysis failed:', error);
  }
  return null;
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!url.startsWith('http')) return;

  const edgeResult = await analyzeURLEdge(url);

  if (edgeResult.score > EDGE_THRESHOLD_BLOCK) {
    chrome.tabs.update(details.tabId, {
      url: chrome.runtime.getURL('warning.html') + '?url=' + encodeURIComponent(url)
    });
    return;
  }

  if (edgeResult.score > EDGE_THRESHOLD_ALLOW) {
    const cloudResult = await analyzeURLCloud(url);
    if (cloudResult && (cloudResult.action === 'block' || cloudResult.action === 'emergency_block')) {
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL('warning.html') + '?url=' + encodeURIComponent(url)
      });
    }
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeURL') {
    analyzeURLCloud(request.url).then(sendResponse);
    return true;
  }
  return false;
});

loadEdgeModels();
