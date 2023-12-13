// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

function generateColor() {
    const colors = ['#FF7F50', '#FFD700', '#32CD32', '#87CEEB', '#FF69B4'];
    const color = colors[colorIndex % colors.length];
    colorIndex++;
    return color;
}

function deleteItem(event) {
    const target = event.target;
    if (target.className === 'highlight') {
      target.remove();
    }
}