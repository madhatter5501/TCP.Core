/** Vary display order without changing the authored indexes used by saved attempts. */
export function orderedChoices(id: string, choices: readonly string[]) {
  const rank = (choice: string) => {
    let hash = 0xcbf29ce484222325n;
    for (const character of `${id}\0${choice}`) {
      hash ^= BigInt(character.codePointAt(0)!);
      hash = BigInt.asUintN(64, hash * 0x100000001b3n);
    }
    return hash;
  };
  return choices.map((choice, index) => ({ choice, index, rank: rank(choice) }))
    .sort((a, b) => a.rank < b.rank ? -1 : a.rank > b.rank ? 1 : a.choice < b.choice ? -1 : a.choice > b.choice ? 1 : 0);
}
