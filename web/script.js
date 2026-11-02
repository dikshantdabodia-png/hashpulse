/**
 * HASHPULSE - PASSWORD SECURITY & VULNERABILITY ANALYZER
 * Pure client-side implementation using:
 *  - Native Web Crypto API (SHA-1 hashing)
 *  - Have I Been Pwned (HIBP) k-Anonymity API
 *  - zxcvbn (Markov entropy modeling, dictionary & pattern detection)
 * 
 * Zero plaintext transmission. 100% local browser execution.
 */

(() => {
  'use strict';

  // DOM Elements
  const passwordInput = document.getElementById('password-input');
  const toggleVisibilityBtn = document.getElementById('toggle-visibility-btn');
  const visibilityIcon = document.getElementById('visibility-icon');
  const generateBtn = document.getElementById('generate-btn');
  const clearBtn = document.getElementById('clear-btn');

  // Meter & Banner
  const meterTrack = document.querySelector('.meter-track');
  const meterSegments = document.querySelectorAll('.meter-segment');
  const strengthLabel = document.getElementById('strength-label');
  const breachBanner = document.getElementById('breach-banner');
  const breachDetail = document.getElementById('breach-detail');

  // Stats
  const statLength = document.getElementById('stat-length');
  const statEntropy = document.getElementById('stat-entropy');
  const statCombinations = document.getElementById('stat-combinations');
  const statHibp = document.getElementById('stat-hibp');
  const statHibpSub = document.getElementById('stat-hibp-sub');

  // Rules
  const ruleLower = document.getElementById('rule-lower');
  const ruleUpper = document.getElementById('rule-upper');
  const ruleNumber = document.getElementById('rule-number');
  const ruleSymbol = document.getElementById('rule-symbol');
  const ruleLength = document.getElementById('rule-length');
  const ruleRepeat = document.getElementById('rule-repeat');

  // Crack Times
  const timeOnline = document.getElementById('time-online');
  const timeOfflineSlow = document.getElementById('time-offline-slow');
  const timeOfflineFast = document.getElementById('time-offline-fast');
  const timeCluster = document.getElementById('time-cluster');

  // Feedback & Patterns
  const feedbackWarning = document.getElementById('feedback-warning');
  const feedbackSuggestions = document.getElementById('feedback-suggestions');
  const detectedSequences = document.getElementById('detected-sequences');

  // State
  let debounceTimer = null;
  let currentAbortController = null;
  let lastCheckedHash = '';

  const STRENGTH_NAMES = [
    'VERY WEAK',
    'WEAK',
    'FAIR',
    'STRONG',
    'VERY STRONG'
  ];

  // ==========================================================================
  // Cryptographic Helper: SHA-1 via Web Crypto API
  // ==========================================================================
  async function computeSha1(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  // ==========================================================================
  // Online Primary Check: HIBP k-Anonymity API
  // ==========================================================================
  async function checkBreachStatus(sha1Hash, signal) {
    const prefix = sha1Hash.substring(0, 5);
    const suffix = sha1Hash.substring(5);

    try {
      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        method: 'GET',
        headers: {
          'Add-Padding': 'true' // Standard privacy padding to resist traffic analysis
        },
        signal
      });

      if (!response.ok) {
        throw new Error(`HIBP API responded with status ${response.status}`);
      }

      const bodyText = await response.text();
      const lines = bodyText.split(/\r?\n/);

      for (const line of lines) {
        const parts = line.split(':');
        if (parts[0] && parts[0].trim().toUpperCase() === suffix) {
          const count = parseInt(parts[1], 10);
          return { breached: true, count: isNaN(count) ? 1 : count };
        }
      }

      return { breached: false, count: 0 };
    } catch (err) {
      if (err.name === 'AbortError') {
        throw err;
      }
      console.warn('HashPulse: HIBP check unavailable, falling back offline:', err.message);
      return { offline: true, error: err.message };
    }
  }

  // ==========================================================================
  // Search Space & Entropy Calculation
  // ==========================================================================
  function calculateComposition(password) {
    const len = password.length;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSymbol = /[^a-zA-Z0-9]/.test(password);
    const hasConsecutiveRepeat = /(.)\1/.test(password);

    let pool = 0;
    if (hasLower) pool += 26;
    if (hasUpper) pool += 26;
    if (hasNumber) pool += 10;
    if (hasSymbol) pool += 33;

    let entropy = 0;
    if (pool > 0 && len > 0) {
      entropy = len * (Math.log(pool) / Math.log(2));
    }

    return {
      length: len,
      hasLower,
      hasUpper,
      hasNumber,
      hasSymbol,
      noRepeats: !hasConsecutiveRepeat,
      pool,
      entropy: entropy.toFixed(1)
    };
  }

  // ==========================================================================
  // Human-Readable Time Formatter
  // ==========================================================================
  function formatCrackTime(seconds) {
    if (!isFinite(seconds) || seconds < 0) return 'INSTANT';
    if (seconds < 1) return 'INSTANT (<1 sec)';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 3153600000) return `${Math.round(seconds / 31536000)} years`;
    if (seconds < 315360000000) return `${Math.round(seconds / 3153600000)} centuries`;
    
    const centuries = seconds / 3153600000;
    if (centuries < 1e9) {
      return `${centuries.toExponential(2)} centuries`;
    }
    return '> 10^12 centuries';
  }

  // ==========================================================================
  // Update UI Elements
  // ==========================================================================
  function updateRule(element, isValid) {
    if (isValid) {
      element.classList.add('valid');
      element.querySelector('.rule-icon').textContent = '[ X ]';
    } else {
      element.classList.remove('valid');
      element.querySelector('.rule-icon').innerHTML = '[ &nbsp; ]';
    }
  }

  function renderPatterns(sequence) {
    detectedSequences.innerHTML = '';
    if (!sequence || sequence.length === 0) {
      detectedSequences.innerHTML = '<span class="tag tag-empty">No recognizable patterns found</span>';
      return;
    }

    let patternCount = 0;
    sequence.forEach(item => {
      if (item.pattern === 'bruteforce' && sequence.length > 1) return;

      const tag = document.createElement('span');
      tag.className = 'tag';

      let label = `${item.pattern.toUpperCase()}`;
      if (item.token) {
        const cleanToken = item.token.length > 12 ? item.token.substring(0, 10) + '...' : item.token;
        label += `: "${cleanToken}"`;
      }
      if (item.dictionary_name) {
        label += ` (${item.dictionary_name})`;
      }
      if (item.l33t) {
        label += ' [LEETSPEAK]';
      }
      if (item.reversed) {
        label += ' [REVERSED]';
      }

      tag.textContent = label;
      detectedSequences.appendChild(tag);
      patternCount++;
    });

    if (patternCount === 0) {
      detectedSequences.innerHTML = '<span class="tag tag-empty">No recognizable dictionary/keyboard patterns</span>';
    }
  }

  function resetToIdle() {
    meterSegments.forEach(seg => seg.classList.remove('active'));
    meterTrack.classList.remove('breached');
    strengthLabel.textContent = 'IDLE (AWAITING INPUT)';
    breachBanner.classList.add('hidden');

    statLength.textContent = '0';
    statEntropy.textContent = '0.0';
    statCombinations.textContent = '0';
    statHibp.textContent = 'UNCHECKED';
    statHibpSub.textContent = 'k-anonymity';

    [ruleLower, ruleUpper, ruleNumber, ruleSymbol, ruleLength, ruleRepeat].forEach(r => updateRule(r, false));

    timeOnline.textContent = '-';
    timeOfflineSlow.textContent = '-';
    timeOfflineFast.textContent = '-';
    timeCluster.textContent = '-';

    feedbackWarning.textContent = 'None identified yet.';
    feedbackSuggestions.innerHTML = '<li>Enter a password to run pattern inspection.</li>';
    detectedSequences.innerHTML = '<span class="tag tag-empty">No recognizable patterns found</span>';
  }

  // ==========================================================================
  // Main Evaluation Coordinator
  // ==========================================================================
  async function evaluatePassword() {
    const password = passwordInput.value;

    if (!password) {
      if (currentAbortController) currentAbortController.abort();
      resetToIdle();
      return;
    }

    // 1. Basic Composition & Pool Entropy
    const comp = calculateComposition(password);
    statLength.textContent = comp.length;
    statEntropy.textContent = comp.entropy;

    updateRule(ruleLower, comp.hasLower);
    updateRule(ruleUpper, comp.hasUpper);
    updateRule(ruleNumber, comp.hasNumber);
    updateRule(ruleSymbol, comp.hasSymbol);
    updateRule(ruleLength, comp.length >= 12);
    updateRule(ruleRepeat, comp.noRepeats);

    // 2. Base Check (Offline zxcvbn)
    let zScore = 0;
    let guesses = 1000;
    let feedback = { warning: '', suggestions: [] };
    let sequence = [];

    if (typeof window.zxcvbn === 'function') {
      const zResult = window.zxcvbn(password);
      zScore = zResult.score;
      guesses = Math.max(zResult.guesses, 1);
      feedback = zResult.feedback || feedback;
      sequence = zResult.sequence || [];
    } else {
      const rawCombinations = Math.pow(comp.pool || 10, comp.length);
      guesses = Math.min(rawCombinations, Number.MAX_SAFE_INTEGER);
      if (comp.entropy < 28) zScore = 0;
      else if (comp.entropy < 40) zScore = 1;
      else if (comp.entropy < 55) zScore = 2;
      else if (comp.entropy < 70) zScore = 3;
      else zScore = 4;
    }

    if (guesses >= 1e12) {
      statCombinations.textContent = guesses.toExponential(2);
    } else {
      statCombinations.textContent = guesses.toLocaleString();
    }

    // Crack Time Estimates
    const targetGuesses = guesses * 0.5;
    timeOnline.textContent = formatCrackTime(targetGuesses / 100);
    timeOfflineSlow.textContent = formatCrackTime(targetGuesses / 10000);
    timeOfflineFast.textContent = formatCrackTime(targetGuesses / 1e11); // 100 GH/s
    timeCluster.textContent = formatCrackTime(targetGuesses / 1e12);     // 1 TH/s

    // Pattern & Feedback UI
    feedbackWarning.textContent = feedback.warning || 'None. No obvious dictionary words or spatial walks detected.';
    feedbackSuggestions.innerHTML = '';
    if (feedback.suggestions && feedback.suggestions.length > 0) {
      feedback.suggestions.forEach(s => {
        const li = document.createElement('li');
        li.textContent = s;
        feedbackSuggestions.appendChild(li);
      });
    } else {
      const li = document.createElement('li');
      li.textContent = zScore >= 3 ? 'Password exhibits strong structural entropy.' : 'Add more length and mix un-patterned words.';
      feedbackSuggestions.appendChild(li);
    }
    renderPatterns(sequence);

    // Initial Meter update based on offline zxcvbn
    meterTrack.classList.remove('breached');
    meterSegments.forEach((seg, idx) => {
      if (idx <= zScore) {
        seg.classList.add('active');
      } else {
        seg.classList.remove('active');
      }
    });
    strengthLabel.textContent = STRENGTH_NAMES[zScore] || 'UNKNOWN';

    // 3. Primary Online Check: Have I Been Pwned (HIBP) k-Anonymity
    if (currentAbortController) {
      currentAbortController.abort();
    }
    currentAbortController = new AbortController();

    statHibp.textContent = 'CHECKING...';
    statHibpSub.textContent = 'querying range';

    try {
      const sha1Hash = await computeSha1(password);
      lastCheckedHash = sha1Hash;

      const timeoutId = setTimeout(() => currentAbortController.abort(), 4000);
      const breachResult = await checkBreachStatus(sha1Hash, currentAbortController.signal);
      clearTimeout(timeoutId);

      if (lastCheckedHash !== sha1Hash) return;

      if (breachResult.breached) {
        // OVERRIDE STRENGTH SCORE
        meterTrack.classList.add('breached');
        meterSegments.forEach(seg => seg.classList.remove('active'));
        strengthLabel.textContent = 'COMPROMISED (PWNED IN BREACH)';

        statHibp.textContent = `BREACHED (${breachResult.count.toLocaleString()}x)`;
        statHibpSub.textContent = 'found in leaks';

        breachDetail.textContent = `This exact password has appeared ${breachResult.count.toLocaleString()} times in publicly disclosed data breaches. Attackers with rainbow tables or wordlists can crack this instantly.`;
        breachBanner.classList.remove('hidden');

        timeOnline.textContent = 'INSTANT (In Wordlists)';
        timeOfflineSlow.textContent = 'INSTANT (In Wordlists)';
        timeOfflineFast.textContent = 'INSTANT (In Wordlists)';
        timeCluster.textContent = 'INSTANT (In Wordlists)';
      } else if (breachResult.offline) {
        statHibp.textContent = 'OFFLINE';
        statHibpSub.textContent = 'checked offline only';
        breachBanner.classList.add('hidden');
      } else {
        statHibp.textContent = 'SAFE (0)';
        statHibpSub.textContent = 'no breaches found';
        breachBanner.classList.add('hidden');
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        console.warn('HashPulse HIBP check error:', err);
        statHibp.textContent = 'OFFLINE';
        statHibpSub.textContent = 'fallback active';
      }
    }
  }

  // ==========================================================================
  // Password Generator
  // ==========================================================================
  function generateStrongPassword(length = 18) {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    const randomValues = new Uint32Array(length);
    crypto.getRandomValues(randomValues);

    let password = '';
    for (let i = 0; i < length; i++) {
      password += charset[randomValues[i] % charset.length];
    }
    return password;
  }

  // ==========================================================================
  // Event Listeners
  // ==========================================================================
  passwordInput.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(evaluatePassword, 300);
  });

  toggleVisibilityBtn.addEventListener('click', () => {
    if (passwordInput.type === 'password') {
      passwordInput.type = 'text';
      visibilityIcon.textContent = '[ HIDE ]';
    } else {
      passwordInput.type = 'password';
      visibilityIcon.textContent = '[ SHOW ]';
    }
  });

  generateBtn.addEventListener('click', () => {
    const strongPassword = generateStrongPassword(18);
    passwordInput.value = strongPassword;
    passwordInput.type = 'text';
    visibilityIcon.textContent = '[ HIDE ]';
    evaluatePassword();
  });

  clearBtn.addEventListener('click', () => {
    passwordInput.value = '';
    resetToIdle();
    passwordInput.focus();
  });

  resetToIdle();
})();
