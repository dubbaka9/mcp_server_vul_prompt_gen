flowchart TD
    A["Fortify or Black Duck Automated Scan for risks"]
    B["Vulnerabilities Details output of identified issues"]
    C["Vul-Fix-Agent-Prompt Generator"]
    C1["LangChain + LLM + Vector DB to provides semantic context"]
    C2["Knowledge base (TOML, Word or YAML) with static remediation logic"]
    D["Generated Remediation Prompt with tailored fix suggestion"]
    E["Git Integration with LLMPrompt drives code update in Git"]
    F["Apply Fixes with patch is committed and MR is opened"]
    G["Human Review or Developer inspects and approves changes"]

    A --> B
    B --> C
    C --> C1
    C --> C2
    C1 --> D
    C2 --> D
    D --> E
    E --> F
    F --> G

    style A fill:#fde2e2,stroke:#333,stroke-width:1px
    style B fill:#fef9e7,stroke:#333,stroke-width:1px
    style C fill:#e0f7fa,stroke:#333,stroke-width:1px
    style C1 fill:#d0ebff,stroke:#333,stroke-width:1px
    style C2 fill:#e1bee7,stroke:#333,stroke-width:1px
    style D fill:#e8f5e9,stroke:#333,stroke-width:1px
    style E fill:#d1c4e9,stroke:#333,stroke-width:1px
    style F fill:#f3e5f5,stroke:#333,stroke-width:1px
    style G fill:#fff3e0,stroke:#333,stroke-width:1px