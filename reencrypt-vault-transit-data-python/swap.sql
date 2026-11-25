-- Simulate a bug that wrote two rows' ciphertexts to each other's rows.
UPDATE findings f
   SET detail = o.detail
  FROM findings o
 WHERE (f.id, o.id) IN ((2660, 2662), (2662, 2660));
