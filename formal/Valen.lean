/-
  VALEN — mechanized formal core (Lean 4, core only, no Mathlib).

  Mechanizes the paper's "formal core":

  * Prop. 1 — soundness of the boolean taint abstraction: an abstract "clean"
    verdict implies that no concrete execution taints the variable.
  * Prop. 2 — the authorization invariant: an authorization edge is a
    privilege escalation, and a path with no authorization edges cannot escalate.

  Build:  lean formal/Valen.lean
-/

namespace Valen

/-! ## 1. The taint lattice -/

abbrev Tag := Nat
abbrev TaintSet := Tag → Prop  -- a predicate; `⊑` is pointwise implication

def TBot : TaintSet := fun _ => False
def TTag (t : Tag) : TaintSet := fun t' => t' = t
def TJoin (a b : TaintSet) : TaintSet := fun t => a t ∨ b t
def TSub (a b : TaintSet) : Prop := ∀ t, a t → b t

theorem TSub.refl (a : TaintSet) : TSub a a := fun _ h => h
theorem TSub.trans {a b c : TaintSet} (hab : TSub a b) (hbc : TSub b c) : TSub a c :=
  fun t h => hbc t (hab t h)

abbrev CState := Nat → TaintSet   -- concrete: a set of tags per variable
abbrev AState := Nat → Prop       -- abstract: tainted (⊤) or clean (⊥) per variable

/-- The abstraction map: abstractly tainted iff some concrete tag reaches it. -/
def alpha (σ : CState) : AState := fun x => ∃ t, σ x t

/-- Abstract monotonicity of states. -/
def AMono (β γ : AState) : Prop := ∀ x, β x → γ x

/-! ## 2. IR and semantics -/

inductive Expr
  | const (t : Tag)
  | var (x : Nat)
  | join (a b : Expr)

inductive Stmt
  | assign (x : Nat) (e : Expr)
  | source (x : Nat) (t : Tag)
  | sanitize (x : Nat)
  | sink (x : Nat) (e : Expr)

abbrev Prog := List Stmt

def evalC (σ : CState) : Expr → TaintSet
  | .const _ => TBot
  | .var x => σ x
  | .join a b => TJoin (evalC σ a) (evalC σ b)

def evalA (β : AState) : Expr → Prop
  | .const _ => False
  | .var x => β x
  | .join a b => evalA β a ∨ evalA β b

def updateC (σ : CState) (x : Nat) (S : TaintSet) : CState :=
  fun y t => (y = x ∧ S t) ∨ (y ≠ x ∧ σ y t)

def updateA (β : AState) (x : Nat) (b : Prop) : AState :=
  fun y => (y = x ∧ b) ∨ (y ≠ x ∧ β y)

def stepC (σ : CState) : Stmt → CState
  | .assign x e => updateC σ x (evalC σ e)
  | .source x t => updateC σ x (TTag t)
  | .sanitize x => updateC σ x TBot
  | .sink _ _ => σ

def stepA (β : AState) : Stmt → AState
  | .assign x e => updateA β x (evalA β e)
  | .source x _ => updateA β x True
  | .sanitize x => updateA β x False
  | .sink _ _ => β

def execC (p : Prog) (σ : CState) : CState := p.foldl stepC σ
def execA (p : Prog) (β : AState) : AState := p.foldl stepA β

/-! ## 3. Soundness (Prop. 1) -/

theorem alpha_update (σ : CState) (x : Nat) (S : TaintSet) :
    ∀ y, alpha (updateC σ x S) y ↔ updateA (alpha σ) x (∃ t, S t) y := by
  intro y
  by_cases h : y = x <;> simp [alpha, updateC, updateA, h]

/-- The fundamental lemma: concrete taint implies abstract taint. -/
theorem evalC_sound (σ : CState) (e : Expr) (t : Tag) :
    evalC σ e t → evalA (alpha σ) e := by
  induction e with
  | const t => intro h; exact h
  | var x => intro h; exact ⟨t, h⟩
  | join a b iha ihb =>
      intro h
      exact h.elim (fun ha => Or.inl (iha ha)) (fun hb => Or.inr (ihb hb))

/-- `evalA` is monotone in the abstract state. -/
theorem evalA_mono {β γ : AState} (h : AMono β γ) (e : Expr) :
    evalA β e → evalA γ e := by
  induction e with
  | const t => intro hc; exact hc
  | var x => intro hx; exact h x hx
  | join a b iha ihb =>
      intro hj
      exact hj.elim (fun ha => Or.inl (iha ha)) (fun hb => Or.inr (ihb hb))

/-- One-step simulation: the abstract step over-approximates the concrete step. -/
theorem step_sound (σ : CState) (β : AState) (h : AMono (alpha σ) β) :
    ∀ s : Stmt, AMono (alpha (stepC σ s)) (stepA β s) := by
  intro s y hy
  cases s with
  | assign x e =>
      have hy' : updateA (alpha σ) x (∃ t, evalC σ e t) y :=
        (alpha_update σ x (evalC σ e) y).mp hy
      rcases hy' with ⟨hyx, hE⟩ | ⟨hyx, hα⟩
      · exact Or.inl ⟨hyx, evalA_mono h e (by rcases hE with ⟨t, ht⟩; exact evalC_sound σ e t ht)⟩
      · exact Or.inr ⟨hyx, h y hα⟩
  | source x t =>
      have hy' : updateA (alpha σ) x (∃ t', TTag t t') y :=
        (alpha_update σ x (TTag t) y).mp hy
      rcases hy' with ⟨hyx, _⟩ | ⟨hyx, hα⟩
      · exact Or.inl ⟨hyx, trivial⟩
      · exact Or.inr ⟨hyx, h y hα⟩
  | sanitize x =>
      have hy' : updateA (alpha σ) x (∃ t, TBot t) y :=
        (alpha_update σ x TBot y).mp hy
      rcases hy' with ⟨hyx, hbot⟩ | ⟨hyx, hα⟩
      · exact Or.inl ⟨hyx, by rcases hbot with ⟨t, ht⟩; exact ht⟩
      · exact Or.inr ⟨hyx, h y hα⟩
  | sink x e => exact h y hy

/-- Program soundness, in invariant form. -/
theorem exec_sound_gen (p : Prog) (σ : CState) (β : AState) (h : AMono (alpha σ) β) :
    AMono (alpha (execC p σ)) (execA p β) := by
  induction p generalizing σ β with
  | nil => exact h
  | cons s rest ih => exact ih (stepC σ s) (stepA β s) (step_sound σ β h s)

theorem exec_sound (p : Prog) (σ : CState) :
    AMono (alpha (execC p σ)) (execA p (alpha σ)) :=
  exec_sound_gen p σ (alpha σ) (fun _ h => h)

/-- **Prop. 1** (soundness of the taint abstraction): if the abstract execution
reports a variable clean, then no concrete execution taints it. -/
theorem prop1_soundness (p : Prog) (σ : CState) (x : Nat) :
    ¬ execA p (alpha σ) x → ¬ ∃ t, execC p σ x t :=
  fun hclean ht => hclean (exec_sound p σ x ht)

/-! ## 4. Naturality of authorization (Prop. 2) -/

/-- An authorization edge strictly raises the privilege level. -/
def Auth (F : Nat → Nat) (u v : Nat) : Prop := F u < F v

theorem auth_is_escalation (F : Nat → Nat) (u v : Nat) : Auth F u v ↔ F u < F v := Iff.rfl

/-- A non-authorization step never escalates. -/
theorem no_auth_no_escalation (F : Nat → Nat) (u v : Nat) (h : ¬ Auth F u v) : F v ≤ F u :=
  Nat.not_lt.mp h

/-- Consecutive non-authorization steps cannot escalate. -/
theorem no_auth_trans (F : Nat → Nat) (a b c : Nat)
    (h1 : ¬ Auth F a b) (h2 : ¬ Auth F b c) : F c ≤ F a :=
  Nat.le_trans (no_auth_no_escalation F b c h2) (no_auth_no_escalation F a b h1)

/-- A path predicate: no consecutive step is an authorization edge. -/
def NoAuth (F : Nat → Nat) : List Nat → Prop
  | [] => True
  | [_] => True
  | a :: b :: rest => (¬ Auth F a b) ∧ NoAuth F (b :: rest)

/-- A path with no authorization edges is level-bounded end to end: the endpoint
cannot have higher privilege than the start. -/
theorem no_auth_bounded (F : Nat → Nat) (a b : Nat) :
    ∀ (mid : List Nat), NoAuth F (a :: (mid ++ [b])) → F b ≤ F a := by
  intro mid
  induction mid generalizing a with
  | nil => intro h; exact no_auth_no_escalation F a b h.1
  | cons c cs ih =>
      intro h
      exact Nat.le_trans (ih c h.2) (no_auth_no_escalation F a c h.1)

end Valen
