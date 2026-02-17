# AI-Driven Parameterized Phishing Email Generator for Employee Security Awareness Training

**Course:** Artificial Intelligence in Cybersecurity

**Submitted by:**

| Name             | Roll Number |
| ---------------- | ----------- |
| Muhammad Sohaib  | 22K-4751    |
| Zeerak Shahzad   | 22K-4692    |

---

## Abstract

Phishing attacks continue to be one of the most pervasive and damaging cybersecurity threats facing modern organizations. Traditional employee awareness training programs rely on static, template-based phishing simulations that quickly become predictable and fail to reflect the dynamic, evolving nature of real-world phishing campaigns. This project proposes the design and implementation of an **AI-driven parameterized phishing email generator** intended exclusively for controlled employee security awareness training. Leveraging Natural Language Processing (NLP) and prompt engineering techniques on pre-trained language models, the system dynamically generates realistic phishing emails with embedded, measurable red-flag indicators—including suspicious attachments, manipulated URLs, link obfuscation, and emotional manipulation triggers such as urgency, authority, fear, and reward. A rule-based Indicator Injection Engine ensures consistent and accurate embedding of selected phishing parameters, while a web-based interface enables trainers to customize scenarios and review highlighted indicators for educational debriefing. By combining artificial intelligence with parameterized security indicators, this project delivers a scalable, non-repetitive, and highly realistic phishing simulation tool that strengthens organizational cyber resilience within a strictly ethical and academic framework.

---

## 1. Introduction

Phishing remains the dominant initial access vector in cyber incidents worldwide. According to the **Verizon Data Breach Investigations Report (DBIR)**, over 80% of security breaches involve a human element, with phishing emails serving as the primary delivery mechanism for credential theft, malware deployment, and social engineering attacks. Attackers continue to exploit both technical weaknesses and human psychological vulnerabilities through deceptive emails that contain suspicious attachments, manipulated links, spoofed URLs, and emotionally persuasive language.

Traditional phishing awareness programs attempt to educate employees by exposing them to simulated phishing emails. However, these programs overwhelmingly rely on **static, pre-written templates** that fail to reflect the evolving sophistication of real phishing campaigns. Employees quickly learn to recognize repeated patterns, rendering the training ineffective over time.

There exists a clear need for an **intelligent, adaptive system** capable of dynamically generating realistic phishing emails while embedding clearly defined and measurable red-flag indicators for training purposes. By harnessing the power of Artificial Intelligence—specifically Natural Language Processing and large language models—it is possible to create a phishing simulation tool that produces diverse, contextually relevant, and technically accurate phishing scenarios on demand.

This project proposes the development of an **AI-Driven Parameterized Phishing Email Generator** designed for use in controlled employee security awareness training environments.

---

## 2. Problem Statement

Despite significant investment in cybersecurity infrastructure, the **human factor** remains the weakest link in organizational defense. Employees frequently fail to detect phishing emails due to the following reasons:

- **Suspicious attachments are overlooked** — files with double extensions (e.g., `salary_update.pdf.exe`), compressed archives, and macro-enabled documents are not scrutinized.
- **Manipulated URLs are not verified** — employees rarely inspect URLs for typosquatting, IP-based addresses, or subdomain spoofing.
- **Hyperlinks hide malicious destinations** — display text often masks the true URL behind a link.
- **Emotional manipulation influences decision-making** — urgency, fear, authority, and reward-based messaging bypasses rational evaluation.

Current phishing awareness tools suffer from critical limitations:

| Limitation                        | Impact                                                       |
| --------------------------------- | ------------------------------------------------------------ |
| Repetitive, static templates     | Employees memorize patterns, reducing training effectiveness |
| Lack of realistic variability    | Simulations fail to mimic real-world attack diversity        |
| No parameterization of indicators | Trainers cannot target specific red flags for assessment     |
| No AI-driven content generation  | Emails lack contextual realism and linguistic sophistication |

**There is a pressing need for an AI-driven system that generates controlled, parameterized phishing emails based on specific technical and psychological indicators**, enabling organizations to deliver effective, scalable, and non-repetitive security awareness training.

---

## 3. Project Objectives

The primary objectives of this project are:

1. **To design and implement an AI-driven phishing email generator** that dynamically produces realistic, context-aware phishing emails using Natural Language Processing techniques.
2. **To embed controlled phishing indicators** within generated emails, including:
   - Suspicious attachments (double extensions, compressed files, macro-enabled documents)
   - Manipulated or spoofed URLs (typosquatting, IP-based, subdomain spoofing)
   - Link obfuscation techniques (hidden URLs, URL shorteners)
   - Emotional manipulation triggers (urgency, authority, fear, reward)
3. **To provide customizable phishing scenarios** through intuitive parameter selection, enabling trainers to target specific vulnerability areas.
4. **To support employee awareness training** within a strictly ethical and controlled academic environment, with all generated content used exclusively for educational purposes.

---

## 4. Scope of the Project

### 4.1 Included Scope

The system focuses strictly on **email-based phishing indicators**, organized into three categories:

#### A. Attachment-Based Indicators

| Indicator Type          | Example                                  |
| ----------------------- | ---------------------------------------- |
| Double file extensions  | `salary_update.pdf.exe`                  |
| Compressed archives     | `.zip` files with suspicious names       |
| Macro-enabled documents | `.docm` files requiring macro execution  |

#### B. Link-Based Indicators

| Indicator Type       | Example                                  |
| -------------------- | ---------------------------------------- |
| IP-based URLs        | `http://192.168.1.45/login`              |
| Typosquatting domains | `micros0ft-support.com`                 |
| URL shorteners       | `bit.ly/3xKz9mQ`                        |
| Subdomain spoofing   | `login.paypal.com.attacker.net`          |
| HTTP instead of HTTPS | `http://company-portal.com/reset`       |

#### C. Emotional Manipulation Indicators

| Trigger Type | Example Phrasing                                        |
| ------------ | ------------------------------------------------------- |
| Urgency      | *"Immediate action required within 24 hours"*           |
| Authority    | *"IT Administrator Security Notice"*                    |
| Fear         | *"Your account will be permanently suspended"*          |
| Reward       | *"Your annual bonus has been approved"*                 |

### 4.2 Excluded Scope

- Actual delivery of phishing emails to real users
- SMS phishing (smishing) or voice phishing (vishing)
- Live malware or payload generation
- Exploitation of real vulnerabilities

---

## 5. Proposed System Architecture

The system architecture comprises three interconnected modules:

```
┌─────────────────────────────────────────────────────────┐
│                   USER INTERFACE (Web)                   │
│  Parameter Selection → Email Display → Red Flag Review   │
└──────────────────────────┬──────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │  AI Email Generation    │
              │  Module (NLP / LLM)     │
              │                         │
              │  • Subject line gen     │
              │  • Email body gen       │
              │  • Tone adjustment      │
              │  • Indicator embedding  │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  Indicator Injection    │
              │  Engine (Rule-Based)    │
              │                         │
              │  • Attachment params    │
              │  • URL manipulation     │
              │  • Consistency checks   │
              └─────────────────────────┘
```

### 5.1 Module 1 — AI-Based Email Generation Module

This module leverages **Natural Language Processing (NLP)** and pre-trained language models to dynamically generate phishing emails.

**Role of AI:**

- Generate realistic, context-aware subject lines and email bodies
- Adjust tone and language based on selected emotional triggers
- Embed selected phishing indicators naturally within the email content
- Ensure linguistic variability to avoid repetitive outputs

**Inputs:**

| Parameter          | Options                                                     |
| ------------------ | ----------------------------------------------------------- |
| Emotional Trigger  | Urgency / Authority / Fear / Reward                         |
| Attachment Type    | Double extension / Compressed / Macro-enabled / None        |
| Link Type          | IP-based / Typosquatting / Shortened / Subdomain spoof / HTTP |
| Context            | HR / IT / Finance / Management                              |

**Outputs:**

- Email subject line
- Email body (HTML-formatted)
- Simulated attachment filename
- Suspicious link embedded in content

**AI Technologies:**

- Pre-trained Large Language Model (local or API-based, e.g., GPT, LLaMA, Mistral)
- Prompt engineering for controlled indicator embedding
- Template-free generation for maximum variability

### 5.2 Module 2 — Indicator Injection Engine

A **rule-based module** that ensures the accuracy and consistency of embedded phishing indicators:

- Validates that selected phishing red flags are correctly embedded in the generated output
- Applies controlled parameterization for attachment names and URL formats
- Maintains consistency between selected indicators and generated email content
- Provides structured metadata for each indicator for post-training analysis

### 5.3 Module 3 — Email Output Interface

A **web-based interface** that enables trainers to:

- Select parameters for phishing email generation
- View the fully generated phishing email in a realistic email preview
- Toggle a **"Red Flag Highlight"** mode that visually annotates embedded indicators
- Export generated emails for use in training campaigns
- Review indicator breakdowns for educational debriefing sessions

---

## 6. Methodology

The project follows an **iterative development methodology** with the following phases:

### Phase 1 — Research & Requirements Analysis

- Literature review on phishing attack patterns and indicators
- Analysis of existing phishing simulation tools and their limitations
- Definition of phishing indicator taxonomy

### Phase 2 — System Design

- Architecture design for the three-module system
- Database schema for parameter storage and email history
- UI/UX wireframing for the web interface

### Phase 3 — AI Model Development

- Selection and configuration of the language model
- Development of prompt engineering strategies for each indicator type
- Testing and fine-tuning for output quality and realism

### Phase 4 — Indicator Engine Development

- Implementation of rule-based validation for each indicator category
- Integration with the AI generation module
- Consistency and accuracy testing

### Phase 5 — Interface Development & Integration

- Web interface development (frontend + backend)
- Full system integration and end-to-end testing
- User acceptance testing with sample scenarios

### Phase 6 — Evaluation & Documentation

- Evaluation of generated email realism and indicator accuracy
- Documentation of findings, limitations, and potential improvements
- Final project report and presentation

---

## 7. Tools and Technologies

| Component              | Technology                                                  |
| ---------------------- | ----------------------------------------------------------- |
| Programming Language   | Python                                                      |
| AI / NLP               | OpenAI API / Hugging Face Transformers / LLaMA / Mistral    |
| Prompt Engineering     | Custom prompt templates with parameter injection            |
| Backend Framework      | Flask / FastAPI                                             |
| Frontend               | HTML, CSS, JavaScript (or React.js)                         |
| Database               | SQLite / PostgreSQL                                         |
| Version Control        | Git / GitHub                                                |
| Deployment             | Local server / Docker (for academic demonstration)          |

---

## 8. Expected Deliverables

1. **Functional AI-Driven Phishing Email Generator** — A working web-based application capable of generating parameterized phishing emails.
2. **Indicator Taxonomy Documentation** — A comprehensive reference of all supported phishing indicators and their parameterization.
3. **Training Demonstration Scenarios** — A set of pre-configured scenarios showcasing the system's capabilities across different contexts (HR, IT, Finance).
4. **Project Report** — A detailed academic report covering the design, implementation, evaluation, and findings of the project.
5. **Source Code Repository** — A version-controlled codebase with documentation.

---

## 9. Ethical Considerations

> **⚠️ This project is strictly academic and intended exclusively for controlled security awareness training.**

- All generated phishing emails are for **educational and research purposes only**.
- The system will **not** deliver emails to real users or interact with live mail servers.
- No actual malware, payloads, or exploits will be generated or deployed.
- The project adheres to the principles of **responsible AI use** and **ethical cybersecurity research**.
- All usage will be confined to a **controlled academic environment** under institutional oversight.

---

## 10. Conclusion

This project addresses a critical gap in employee cybersecurity training by introducing an AI-driven, parameterized approach to phishing email generation. By leveraging Natural Language Processing and rule-based indicator injection, the system produces diverse, realistic, and measurable phishing simulations that significantly enhance the effectiveness of security awareness programs. The proposed system moves beyond static templates to deliver a scalable, intelligent, and ethically responsible training tool—contributing to both academic research and practical organizational cyber resilience.

---

## References

1. Verizon. (2024). *Data Breach Investigations Report (DBIR)*. Verizon Enterprise Solutions.
2. APWG. (2024). *Phishing Activity Trends Report*. Anti-Phishing Working Group.
3. Almomani, A., et al. (2013). *A survey of phishing email filtering techniques*. IEEE Communications Surveys & Tutorials.
4. Volkamer, M., et al. (2017). *User experiences of anti-phishing tools*. Journal of Information Security and Applications.
5. Brown, T., et al. (2020). *Language models are few-shot learners*. Advances in Neural Information Processing Systems (NeurIPS).
6. NIST. (2023). *Phishing Resistance in Cybersecurity Awareness Programs*. National Institute of Standards and Technology.

---

*Submitted for academic evaluation in the course: Artificial Intelligence in Cybersecurity*
