;; ChronoVault - Decentralized Temporal Integrity Platform

;; Provides cryptographically verifiable timestamp services via
;; Temporal Proof Certificates (TPCs) with confidence scoring
;; and multi-source time validation.

;; ============================================================
;; CONSTANTS
;; ============================================================

(define-constant CONTRACT-OWNER tx-sender)

;; Error codes
(define-constant ERR-NOT-AUTHORIZED        (err u100))
(define-constant ERR-ALREADY-EXISTS        (err u101))
(define-constant ERR-NOT-FOUND             (err u102))
(define-constant ERR-INVALID-CONFIDENCE    (err u103))
(define-constant ERR-ORACLE-NOT-REGISTERED (err u104))
(define-constant ERR-INVALID-CATEGORY      (err u105))
(define-constant ERR-ALREADY-VALIDATED     (err u106))
(define-constant ERR-INSUFFICIENT-ORACLES  (err u107))

;; TPC categories (maps to use-case domains)
;; 0 = pharmaceutical, 1 = financial, 2 = legal,
;; 3 = supply-chain,   4 = academic
(define-constant CATEGORY-PHARMA       u0)
(define-constant CATEGORY-FINANCIAL    u1)
(define-constant CATEGORY-LEGAL        u2)
(define-constant CATEGORY-SUPPLY-CHAIN u3)
(define-constant CATEGORY-ACADEMIC     u4)

;; Confidence score range: 0-100
(define-constant MAX-CONFIDENCE u100)

;; Minimum oracle votes required before a TPC is considered finalized
(define-constant MIN-ORACLE-VOTES u3)

;; High-stakes threshold: confidence must exceed this to skip
;; escalation to additional validation layers
(define-constant HIGH-STAKES-THRESHOLD u80)

;; ============================================================
;; DATA MAPS AND VARS
;; ============================================================

;; Tracks the next TPC identifier
(define-data-var tpc-nonce uint u0)

;; Registered oracle nodes
;; key: oracle principal
;; value: { active, description-hash }
(define-map oracles
  principal
  { active: bool, description-hash: (buff 32) }
)

;; Temporal Proof Certificates
;; key: tpc-id (uint)
;; value: full certificate data
(define-map tpcs
  uint
  {
    submitter:          principal,
    document-hash:      (buff 32),   ;; SHA-256 of the document
    category:           uint,
    block-height:       uint,        ;; Stacks block at submission
    burn-block-height:  uint,        ;; Bitcoin anchor block
    confidence-score:   uint,        ;; 0-100, updated by oracle votes
    oracle-vote-count:  uint,
    finalized:          bool,
    escalated:          bool         ;; true if sent to additional validation
  }
)

;; Per-TPC oracle votes to prevent double-voting
;; key: { tpc-id, oracle }
(define-map oracle-votes
  { tpc-id: uint, oracle: principal }
  { confidence: uint, voted-at-block: uint }
)

;; Running sum of confidence scores per TPC (for average calculation)
(define-map tpc-confidence-sum
  uint
  uint
)

;; ============================================================
;; PRIVATE HELPERS
;; ============================================================

;; Compute integer average confidence from sum and vote count
(define-private (compute-average-confidence (sum uint) (votes uint))
  (if (is-eq votes u0)
    u0
    (/ sum votes)
  )
)

;; Validate that a category value is within the defined range
(define-private (valid-category? (cat uint))
  (or
    (is-eq cat CATEGORY-PHARMA)
    (or
      (is-eq cat CATEGORY-FINANCIAL)
      (or
        (is-eq cat CATEGORY-LEGAL)
        (or
          (is-eq cat CATEGORY-SUPPLY-CHAIN)
          (is-eq cat CATEGORY-ACADEMIC)
        )
      )
    )
  )
)

;; ============================================================
;; ORACLE MANAGEMENT (owner only)
;; ============================================================

;; Register a new oracle node
(define-public (register-oracle (oracle principal) (description-hash (buff 32)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (asserts! (is-none (map-get? oracles oracle)) ERR-ALREADY-EXISTS)
    (ok (map-set oracles oracle
      { active: true, description-hash: description-hash }
    ))
  )
)

;; Deactivate an oracle node
(define-public (deactivate-oracle (oracle principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (let ((entry (unwrap! (map-get? oracles oracle) ERR-NOT-FOUND)))
      (ok (map-set oracles oracle
        (merge entry { active: false })
      ))
    )
  )
)

;; Reactivate an oracle node
(define-public (reactivate-oracle (oracle principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (let ((entry (unwrap! (map-get? oracles oracle) ERR-NOT-FOUND)))
      (ok (map-set oracles oracle
        (merge entry { active: true })
      ))
    )
  )
)

;; ============================================================
;; TPC SUBMISSION
;; ============================================================

;; Submit a new Temporal Proof Certificate for a document hash
;; Anyone can submit; oracle validation follows separately.
(define-public (submit-tpc
    (document-hash (buff 32))
    (category      uint)
  )
  (let
    (
      (tpc-id (var-get tpc-nonce))
    )
    (asserts! (valid-category? category) ERR-INVALID-CATEGORY)
    (asserts! (is-none (map-get? tpcs tpc-id)) ERR-ALREADY-EXISTS)

    ;; Store the certificate
    (map-set tpcs tpc-id
      {
        submitter:         tx-sender,
        document-hash:     document-hash,
        category:          category,
        block-height:      block-height,
        burn-block-height: burn-block-height,
        confidence-score:  u0,
        oracle-vote-count: u0,
        finalized:         false,
        escalated:         false
      }
    )
    ;; Initialise the confidence sum
    (map-set tpc-confidence-sum tpc-id u0)
    ;; Advance nonce
    (var-set tpc-nonce (+ tpc-id u1))
    (ok tpc-id)
  )
)

;; ============================================================
;; ORACLE VALIDATION
;; ============================================================

;; An active oracle casts a confidence vote for an existing TPC.
;; Once MIN-ORACLE-VOTES is reached the TPC is finalized and
;; escalated when average confidence falls below HIGH-STAKES-THRESHOLD.
(define-public (cast-oracle-vote
    (tpc-id    uint)
    (confidence uint)
  )
  (let
    (
      (oracle-entry (unwrap! (map-get? oracles tx-sender)
                             ERR-ORACLE-NOT-REGISTERED))
      (tpc          (unwrap! (map-get? tpcs tpc-id) ERR-NOT-FOUND))
      (vote-key     { tpc-id: tpc-id, oracle: tx-sender })
      (prior-sum    (default-to u0 (map-get? tpc-confidence-sum tpc-id)))
    )
    ;; Oracle must be active
    (asserts! (get active oracle-entry) ERR-NOT-AUTHORIZED)
    ;; TPC must not already be finalized
    (asserts! (not (get finalized tpc)) ERR-ALREADY-VALIDATED)
    ;; Confidence must be in range
    (asserts! (<= confidence MAX-CONFIDENCE) ERR-INVALID-CONFIDENCE)
    ;; No double-voting
    (asserts! (is-none (map-get? oracle-votes vote-key)) ERR-ALREADY-VALIDATED)

    ;; Record the vote
    (map-set oracle-votes vote-key
      { confidence: confidence, voted-at-block: block-height }
    )

    (let
      (
        (new-vote-count (+ (get oracle-vote-count tpc) u1))
        (new-sum        (+ prior-sum confidence))
        (avg-confidence (compute-average-confidence new-sum new-vote-count))
        ;; Finalize once minimum votes are reached
        (should-finalize (>= new-vote-count MIN-ORACLE-VOTES))
        ;; Escalate if average confidence is below high-stakes threshold
        (should-escalate (and should-finalize
                              (< avg-confidence HIGH-STAKES-THRESHOLD)))
      )
      ;; Update running sum
      (map-set tpc-confidence-sum tpc-id new-sum)
      ;; Update TPC record
      (ok (map-set tpcs tpc-id
        (merge tpc
          {
            oracle-vote-count: new-vote-count,
            confidence-score:  avg-confidence,
            finalized:         should-finalize,
            escalated:         should-escalate
          }
        )
      ))
    )
  )
)

;; ============================================================
;; READ-ONLY QUERIES
;; ============================================================

;; Retrieve a full TPC record
(define-read-only (get-tpc (tpc-id uint))
  (map-get? tpcs tpc-id)
)

;; Retrieve oracle registration info
(define-read-only (get-oracle (oracle principal))
  (map-get? oracles oracle)
)

;; Retrieve a specific oracle vote for a TPC
(define-read-only (get-oracle-vote (tpc-id uint) (oracle principal))
  (map-get? oracle-votes { tpc-id: tpc-id, oracle: oracle })
)

;; Check whether a TPC is finalized (has reached minimum oracle votes)
(define-read-only (is-finalized (tpc-id uint))
  (match (map-get? tpcs tpc-id)
    tpc (get finalized tpc)
    false
  )
)

;; Return the current confidence score for a TPC (0 if not found)
(define-read-only (get-confidence (tpc-id uint))
  (match (map-get? tpcs tpc-id)
    tpc (get confidence-score tpc)
    u0
  )
)

;; Return the total number of TPCs submitted so far
(define-read-only (get-tpc-count)
  (var-get tpc-nonce)
)
