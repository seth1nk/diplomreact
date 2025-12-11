import React from 'react';
import styled from 'styled-components';

const Button = () => {
  return (
    <StyledWrapper>
      <div className="btn-wrapper">
        <button className="btn">
          <span className="btn-txt">REC</span>
          <div className="dot pulse" />
        </button>
      </div>
    </StyledWrapper>
  );
}

const StyledWrapper = styled.div`
  .btn-wrapper {
    /* Масштабируем кнопку, чтобы она была компактной */
    transform: scale(0.7); 
    transform-origin: center right;
    
    --width: 120px;
    --height: 50px;
    --padding: 4px;
    --border-radius: 30px;
    --dot-size: 10px;
    --btn-color: #202020;
    --hue: 355deg;
    --animation-duration: 1.2s;

    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    width: var(--width);
    height: var(--height);
    border-radius: var(--border-radius);
    border: none;
    background-color: rgba(0,0,0,0.1);
    box-shadow: 1px 1px 2px 0 rgba(255,255,255,0.1), 2px 2px 2px rgba(0,0,0,0.1) inset;
    user-select: none;
    z-index: 1;
  }

  .btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 0;
    width: calc(100% - 2 * var(--padding));
    height: calc(100% - 2 * var(--padding));
    border-radius: calc(var(--border-radius) - var(--padding));
    border: none;
    cursor: pointer;
    background: linear-gradient(rgba(255,255,255,0.1), rgba(0,0,0,0.1)), var(--btn-color);
    box-shadow: 0 4px 8px rgba(0,0,0,0.3);
    transition: all 0.2s ease;
    z-index: 2;
  }

  .btn-txt {
    font-size: 14px;
    font-weight: 800;
    font-family: monospace;
    letter-spacing: 1px;
    color: #fff;
    text-transform: uppercase;
  }

  .dot {
    position: relative;
    width: var(--dot-size);
    height: var(--dot-size);
    border-radius: 50%;
    background-color: #ff0000;
    box-shadow: 0 0 10px #ff0000;
  }

  /* Анимация пульсации */
  .pulse {
    animation: pulse-red 1.5s infinite;
  }

  @keyframes pulse-red {
    0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(255, 0, 0, 0.7); }
    70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(255, 0, 0, 0); }
    100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(255, 0, 0, 0); }
  }

  .btn:hover {
    transform: translateY(-1px);
    filter: brightness(1.2);
  }
  .btn:active {
    transform: translateY(1px);
    filter: brightness(0.9);
  }
`;

export default Button;
