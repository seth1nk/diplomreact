import React from 'react';
import styled from 'styled-components';

const Radar = () => {
  return (
    <StyledWrapper>
      <div className="loader">
        <span />
      </div>
    </StyledWrapper>
  );
}

const StyledWrapper = styled.div`
  .loader {
    position: relative;
    width: 120px; 
    height: 120px;
    background: var(--glass-bg); 
    border-radius: 50%;
    box-shadow: 0 0 50px var(--shadow-color);
    border: 1px solid var(--text-color);
    opacity: 0.8;
    display: flex; 
    align-items: center; 
    justify-content: center; 
    overflow: hidden;
  }
  .loader::before {
    content: ''; 
    position: absolute; 
    inset: 20px; 
    background: transparent;
    border: 1px dashed var(--text-color); 
    opacity: 0.3;
    border-radius: 50%;
  }
  .loader::after {
    content: ''; 
    position: absolute; 
    width: 40px; 
    height: 40px; 
    border-radius: 50%;
    border: 1px dashed var(--text-color);
    opacity: 0.5;
  }
  .loader span {
    position: absolute; 
    top: 50%; 
    left: 50%; 
    width: 50%; 
    height: 100%;
    background: transparent; 
    transform-origin: top left;
    animation: radar81 2s linear infinite; 
    border-top: 1px dashed var(--text-color);
  }
  .loader span::before {
    content: ''; 
    position: absolute; 
    top: 0; 
    left: 0; 
    width: 100%; 
    height: 100%;
    background: var(--accent-color);
    transform-origin: top left; 
    transform: rotate(-55deg);
    filter: blur(30px) drop-shadow(20px 20px 20px var(--accent-color));
    opacity: 0.6;
  }
  @keyframes radar81 { 
    0% { transform: rotate(0deg); } 
    100% { transform: rotate(360deg); } 
  }
`;

export default Radar;
